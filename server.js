const express = require('express');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const Database = require('better-sqlite3');
const session = require('express-session');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database ─────────────────────────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'queue.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS auth (
    id      INTEGER PRIMARY KEY,
    access_token  TEXT,
    refresh_token TEXT,
    token_expiry  INTEGER,
    user_id  TEXT,
    username TEXT
  );
  CREATE TABLE IF NOT EXISTS queue (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tweet1       TEXT NOT NULL,
    tweet2       TEXT NOT NULL,
    scheduled_at INTEGER NOT NULL,
    status       TEXT DEFAULT 'pending',
    posted_at    INTEGER,
    tweet1_id    TEXT,
    tweet2_id    TEXT,
    error        TEXT,
    created_at   INTEGER DEFAULT (unixepoch()),
    condition_id TEXT,
    market_title TEXT
  );
`);

// Migrate existing queue table if columns missing
const qCols = db.prepare('PRAGMA table_info(queue)').all().map(c => c.name);
if (!qCols.includes('condition_id')) db.exec('ALTER TABLE queue ADD COLUMN condition_id TEXT');
if (!qCols.includes('market_title'))  db.exec('ALTER TABLE queue ADD COLUMN market_title TEXT');
if (!qCols.includes('entry_price'))   db.exec('ALTER TABLE queue ADD COLUMN entry_price INTEGER');

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.static('public'));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ── Twitter config ────────────────────────────────────────────────────────────
const TWITTER_API_KEY    = process.env.TWITTER_CLIENT_ID;      // OAuth 1.0a consumer key
const TWITTER_API_SECRET = process.env.TWITTER_CLIENT_SECRET;  // OAuth 1.0a consumer secret
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://evbettors-tweet-tool.onrender.com/auth/twitter/callback';

// ── OAuth 1.0a signing (using battle-tested oauth-1.0a library) ──────────────
const oauth = OAuth({
  consumer: { key: TWITTER_API_KEY, secret: TWITTER_API_SECRET },
  signature_method: 'HMAC-SHA1',
  hash_function(baseString, key) {
    return crypto.createHmac('sha1', key).update(baseString).digest('base64');
  }
});

// Build an OAuth 1.0a Authorization header
// token: { key, secret } or null (for request-token step)
// requestData: { url, method, data? }
function oauth1Header(method, url, userToken, userSecret, extraData = {}) {
  const requestData = { url, method, data: extraData };
  const token = userToken ? { key: userToken, secret: userSecret || '' } : undefined;
  const authData = oauth.authorize(requestData, token);
  return oauth.toHeader(authData).Authorization;
}

// ── Token management ──────────────────────────────────────────────────────────
// Returns { token, secret } — OAuth 1.0a user tokens stored in DB
function getStoredTokens() {
  const auth = db.prepare('SELECT * FROM auth WHERE id = 1').get();
  if (!auth?.access_token || !auth?.refresh_token) {
    throw new Error('Not connected. Click "Connect Twitter" first.');
  }
  return { token: auth.access_token, secret: auth.refresh_token };
}

// ── Twitter API helper (v2, signed with OAuth 1.0a) ──────────────────────────
async function twitterFetch(method, endpoint, body) {
  const { token, secret } = getStoredTokens();
  const url = `https://api.twitter.com/2${endpoint}`;
  // JSON bodies are not included in OAuth 1.0a signature base string
  const authHeader = oauth1Header(method, url, token, secret);
  const res = await fetch(url, {
    method,
    headers: {
      Authorization:  authHeader,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  return res;
}

// ── Upload media to Twitter v1.1 (OAuth 1.0a required) ───────────────────────
async function uploadMedia(buffer, mimeType) {
  const { token, secret } = getStoredTokens();
  const base64   = buffer.toString('base64');
  const category = mimeType.startsWith('image/gif') ? 'tweet_gif' : 'tweet_image';
  const uploadUrl = 'https://upload.twitter.com/1.1/media/upload.json';

  // Sign with OAuth 1.0a — no body params in signature for multipart/form-data
  const authHeader = oauth1Header('POST', uploadUrl, token, secret);

  // MUST use multipart/form-data (not url-encoded) so body params stay out of
  // the OAuth signature base string. With url-encoded, OAuth 1.0a requires ALL
  // body params in the signature — but media_data is too large to sign.
  // Send media_data (base64 string) as a multipart text field.
  // This keeps it out of the OAuth signature while still being accepted by Twitter.
  const formData = new FormData();
  formData.append('media_data', base64);
  formData.append('media_category', category);

  console.log(`[media] Uploading ${mimeType} (${Math.round(buffer.length / 1024)}KB), category=${category}`);

  const res = await fetch(uploadUrl, {
    method:  'POST',
    headers: { Authorization: authHeader },
    // Let fetch set Content-Type with multipart boundary automatically
    body: formData
  });
  const text = await res.text();
  console.log(`[media] Twitter response ${res.status}:`, text.slice(0, 500));
  if (!res.ok) throw new Error(`Media upload ${res.status}: ${text.slice(0, 400)}`);
  const json = JSON.parse(text);
  console.log(`[media] Got media_id_string: ${json.media_id_string}`);
  return json.media_id_string;
}

// ── Post a thread ─────────────────────────────────────────────────────────────
// slipFile / toolFile are optional { buffer, mimetype } objects
// Returns { tweet1Id, tweet2Id, mediaErrors[] }
async function postThread(tweet1, tweet2, slipFile, toolFile) {
  // Upload images if provided (slip → tweet1, tool card → tweet2)
  const tweet1Body = { text: tweet1 };
  const tweet2Body = { text: tweet2 };
  const mediaErrors = [];

  if (slipFile?.buffer) {
    try {
      const mediaId = await uploadMedia(slipFile.buffer, slipFile.mimetype);
      tweet1Body.media = { media_ids: [mediaId] };
    } catch (e) {
      console.error('[media] Slip upload failed:', e.message);
      mediaErrors.push(`Slip: ${e.message}`);
    }
  }

  if (toolFile?.buffer) {
    try {
      const mediaId = await uploadMedia(toolFile.buffer, toolFile.mimetype);
      tweet2Body.media = { media_ids: [mediaId] };
    } catch (e) {
      console.error('[media] Tool card upload failed:', e.message);
      mediaErrors.push(`Tool card: ${e.message}`);
    }
  }

  const r1 = await twitterFetch('POST', '/tweets', tweet1Body);
  const d1 = await r1.json();
  if (!r1.ok) throw new Error(d1.detail || d1.title || JSON.stringify(d1));

  const tweet1Id = d1.data.id;

  tweet2Body.reply = { in_reply_to_tweet_id: tweet1Id };
  const r2 = await twitterFetch('POST', '/tweets', tweet2Body);
  const d2 = await r2.json();
  if (!r2.ok) throw new Error(d2.detail || d2.title || JSON.stringify(d2));

  return { tweet1Id, tweet2Id: d2.data.id, mediaErrors };
}

// ── OAuth 1.0a 3-legged auth routes ──────────────────────────────────────────
// Step 1: get a request token, redirect user to Twitter to authorize
app.get('/auth/twitter', async (req, res) => {
  try {
    const requestTokenUrl = 'https://api.twitter.com/oauth/request_token';
    const authHeader = oauth1Header('POST', requestTokenUrl, null, null, {
      oauth_callback: CALLBACK_URL
    });
    const r = await fetch(requestTokenUrl, {
      method: 'POST',
      headers: { Authorization: authHeader }
    });
    const text = await r.text();
    if (!r.ok) throw new Error(`Request token failed ${r.status}: ${text}`);

    const p = new URLSearchParams(text);
    const oauthToken  = p.get('oauth_token');
    const oauthSecret = p.get('oauth_token_secret');
    if (!oauthToken) throw new Error('No oauth_token in response: ' + text);

    req.session.requestTokenSecret = oauthSecret;
    res.redirect(`https://api.twitter.com/oauth/authorize?oauth_token=${oauthToken}`);
  } catch (err) {
    console.error('OAuth 1.0a request token error:', err);
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

// Step 2: Twitter redirects back with oauth_token + oauth_verifier
app.get('/auth/twitter/callback', async (req, res) => {
  const { oauth_token, oauth_verifier, denied } = req.query;
  if (denied) return res.redirect('/?error=auth_denied');

  try {
    const requestSecret  = req.session.requestTokenSecret || '';
    const accessTokenUrl = 'https://api.twitter.com/oauth/access_token';
    const authHeader     = oauth1Header('POST', accessTokenUrl, oauth_token, requestSecret, {
      oauth_verifier
    });
    const r = await fetch(accessTokenUrl, {
      method:  'POST',
      headers: { Authorization: authHeader, 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({ oauth_verifier })
    });
    const text = await r.text();
    if (!r.ok) throw new Error(`Access token failed ${r.status}: ${text}`);

    const p              = new URLSearchParams(text);
    const accessToken    = p.get('oauth_token');
    const accessSecret   = p.get('oauth_token_secret');
    const userId         = p.get('user_id')     || 'unknown';
    const username       = p.get('screen_name') || 'unknown';

    // Reuse existing columns: access_token = oauth_token, refresh_token = oauth_token_secret
    // token_expiry set far in the future (OAuth 1.0a tokens don't expire)
    const farFuture = Date.now() + 100 * 365 * 24 * 60 * 60 * 1000;
    const existing  = db.prepare('SELECT id FROM auth WHERE id = 1').get();
    if (existing) {
      db.prepare('UPDATE auth SET access_token=?,refresh_token=?,token_expiry=?,user_id=?,username=? WHERE id=1')
        .run(accessToken, accessSecret, farFuture, userId, username);
    } else {
      db.prepare('INSERT INTO auth (id,access_token,refresh_token,token_expiry,user_id,username) VALUES (1,?,?,?,?,?)')
        .run(accessToken, accessSecret, farFuture, userId, username);
    }
    res.redirect('/?connected=1');
  } catch (err) {
    console.error('OAuth 1.0a callback error:', err);
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

app.get('/auth/status', (req, res) => {
  const auth = db.prepare('SELECT username FROM auth WHERE id = 1').get();
  res.json({ connected: !!auth, username: auth?.username || null });
});

app.post('/auth/disconnect', (req, res) => {
  db.prepare('DELETE FROM auth WHERE id = 1').run();
  res.json({ success: true });
});

// ── Polymarket ────────────────────────────────────────────────────────────────
const POLYMARKET_ADDRESS = '0x691A3a1919F2eE338b10FD2F216dF525da34D113';

// Fetch all positions for the wallet
app.get('/api/positions', async (req, res) => {
  try {
    const r = await fetch(
      `https://data-api.polymarket.com/positions?user=${POLYMARKET_ADDRESS}&sizeThreshold=0`
    );
    const data = await r.json();
    res.json(Array.isArray(data) ? data : []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Match tool card image directly against a provided list of positions (single Claude call)
app.post('/api/match-position', upload.single('toolCard'), async (req, res) => {
  try {
    const file = req.file;
    const positions = JSON.parse(req.body.positions || '[]');
    if (!file) return res.status(400).json({ error: 'No image' });
    if (!positions.length) return res.json({ index: null });

    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const list = positions.map((p, i) => `${i}: ${p.title} (${p.outcome || '?'})`).join('\n');

    const msg = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 20,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: file.mimetype, data: file.buffer.toString('base64') } },
          { type: 'text', text: `This is a Prediction Insiders tool card screenshot showing a sports bet on Polymarket.

Look at the tool card and identify:
- Team A (one team in the matchup)
- Team B (the other team / opponent)
- Which team the bet is ON

Here are the user's open Polymarket positions:
${list}

Find the position whose title contains BOTH team names from the specific matchup shown in the tool card. The correct match must include both teams — not just one team name. If a team appears in multiple positions (e.g. "Louisville vs UNC" and "Louisville vs South Florida"), you MUST match the one with the correct opponent.

Reply with ONLY the index number of the correct match. If no position contains both teams from the matchup, reply with -1.` }
        ]
      }]
    });

    const idx = parseInt(msg.content[0].text.trim(), 10);
    res.json({ index: (isNaN(idx) || idx < 0) ? null : idx });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generate a Quote Tweet for a resolved winning position
app.post('/generate-qt', async (req, res) => {
  try {
    const { originalTweet, marketTitle, entryPrice, cashPaidOut, payout } = req.body;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const payoutStr = cashPaidOut || payout;
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 350,
      temperature: 1,
      messages: [{
        role: 'user',
        content: `Write a Quote Tweet celebrating this winning Polymarket prediction that just resolved YES at 100c.

Original tweet that called the play:
"${originalTweet}"

Result:
- Market: ${marketTitle}
- Resolved YES at 100c (full settlement)
- Entry price: ~${entryPrice}c
${payoutStr ? `- Payout: $${Number(payoutStr).toFixed(2)}` : ''}

Hard requirements:
- Under 240 characters total
- NEVER use em dashes (the — character)
- No "I told you so" tone — just clean confidence
- No dramatic one-word sentences like "Called." or "Win."
- No motivational poster phrasing
- Reference that this was a Prediction Insiders signal
- Naturally include oddsjam.com/prediction/insiders
- No standalone CTA sentence

Return ONLY the QT text, nothing else.`
      }]
    });
    res.json({ qt: msg.content[0].text.trim() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Winners: posted tweets cross-referenced with resolved Polymarket positions
app.get('/api/winners', async (req, res) => {
  try {
    const posted = db.prepare(`
      SELECT * FROM queue
      WHERE status = 'posted'
      ORDER BY posted_at DESC LIMIT 100
    `).all();

    // Fetch all positions (open + resolved) from Polymarket
    let positions = [];
    try {
      const r = await fetch(
        `https://data-api.polymarket.com/positions?user=${POLYMARKET_ADDRESS}&sizeThreshold=0`
      );
      const d = await r.json();
      if (Array.isArray(d)) positions = d;
    } catch (e) { /* continue without position data */ }

    // Match a DB item to a Polymarket position using market title keywords + entry price
    function matchPosition(item, positions) {
      if (!item.market_title || !item.entry_price) return null;
      const targetPrice = item.entry_price / 100; // cents → decimal (e.g. 66 → 0.66)
      const keywords = item.market_title.toLowerCase()
        .replace(/[^a-z0-9\s.\-]/g, ' ').split(/\s+/).filter(w => w.length > 2);

      let best = null, bestScore = 0;
      for (const pos of positions) {
        const posTitle = (pos.market || pos.title || pos.question || '').toLowerCase();
        // Price must be within 3 cents — this alone eliminates almost all wrong matches
        if (pos.avgPrice != null && Math.abs(pos.avgPrice - targetPrice) > 0.03) continue;
        const hits = keywords.filter(w => posTitle.includes(w)).length;
        const score = keywords.length ? hits / keywords.length : 0;
        if (score > bestScore && score >= 0.25) { bestScore = score; best = pos; }
      }
      return best;
    }

    const annotated = posted.map(item => {
      const pos = matchPosition(item, positions);
      let won = false;
      if (pos) {
        if (pos.redeemed && pos.cashPaidOut > 0) won = true;
        else if (pos.size > 0 && pos.currentValue >= pos.size * 0.99) won = true;
        else if (pos.winnings > 0) won = true;
      }
      return { ...item, position: pos, won };
    });

    annotated.sort((a, b) => {
      if (a.won !== b.won) return a.won ? -1 : 1;
      return (b.posted_at || 0) - (a.posted_at || 0);
    });

    res.json(annotated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AI generation ─────────────────────────────────────────────────────────────
const VIDEO_URL = 'https://youtu.be/1BmHOrxIET4';

const SYSTEM_PROMPT = `You are a tweet writer for Prediction Insiders, a tool on OddsJam that tracks sharp insider bets on Polymarket prediction markets.

The user will provide one or two screenshots:
- A screenshot from the Prediction Insiders tool (required) — either the mobile card or the desktop expanded card
- Optionally, a screenshot of their Polymarket betting slip

Your job is to write a 2-tweet thread that announces the play and breaks down why the tool flagged it.

---

HOW TO READ THE TOOL CARD SCREENSHOT:

The tool card may appear in two layouts — mobile (compact card) or desktop (expanded card). Both contain the same data fields:

SCORE
- Large number displayed prominently (e.g. 88, 82, 85) — this is the score out of 100

WHY THIS BET section (these three fields are always grouped together):
- Rel. Bet Size — a multiplier like 1.3x or 0.5x. How large this bet is relative to the insider's typical bet size
- Bet size — a dollar amount like $62.0k or $4.8k. The total amount the insider placed on this position
- Slippage — shown as a percentage with a +/- sign, like +1.4% or -6.3%
  - Positive slippage: the market has moved UP since the insider entered (favorable — insider is winning)
  - Negative slippage: the market has moved DOWN since the insider entered (insider's position is underwater)

INSIDER STATS section:
- Sports ROI — a percentage like +8.2% or +9.5%. The insider's historical return on sports bets. This is the credibility anchor.
- Total ROI — overall ROI across all bets (may be same as Sports ROI)
- Trades — total number of trades this insider has made (e.g. 1945, 11199). Larger sample = more meaningful ROI

PRICE / CURRENT PRICE:
- The current market price in cents, shown prominently (e.g. 71¢, 30¢, 48¢)
- On desktop: the price chart labels "Insider entry" (e.g. 70.0¢) and "Current" separately
- On the list/header row: the price tag icon shows the insider's entry price in cents

Derive insider entry price if not directly visible: current price minus slippage amount. For example, if current is 71¢ and slippage is +1.4¢, insider entered at ~69.6¢. Only include the entry price if you can read or reasonably derive it — do not fabricate it.

---

HARD RULES — never break these:
- NEVER use em dashes (the — character). This means the character that looks like a long dash between words. Zero exceptions, zero tolerance. If you are about to write "—", stop and rewrite the sentence using a comma, colon, period, or line break instead.
- Never fabricate or estimate numbers. Use only what is visible in the screenshots.
- Keep tweet 1 under 220 characters.
- Tweet 2 must include all 3 data points from WHY THIS BET + INSIDER STATS: bet size and relative size, slippage context, sports ROI.
- End tweet 2 with the score out of 100 and what that score signals.
- When referencing the tool with a link, the URL must always follow a colon. Correct: "the @OddsJam Prediction Insiders tool: oddsjam.com/prediction/insiders". Never place the word "at" directly before the URL. Wrong: "tool at oddsjam.com/..." — always a colon, never "at".

BANNED PHRASES AND SENTENCE STRUCTURES — never use any of these, even paraphrased:

Clichés:
- "That's not noise"
- "Worth tracking" / "Worth watching"
- "Game changer"
- "This is huge"
- "You don't want to miss"
- "Do your own research"
- "The money is moving"
- "Follow the smart money"
- "The data is screaming" / "The data doesn't lie" / any sentence that personifies data dramatically
- "When the score hits X, [dramatic statement]"

AI writing patterns (these make tweets sound robotic and corny — never use them):
- The "not X, it's Y" / "not X. It's Y." contrast structure. Banned in all forms, including softer versions like "not going all-in, but putting real money behind it" or "not a max-send, but still significant". Do not use contrast framing to describe the bet or the insider at all.
- Rhetorical statements that answer themselves: "Is this a lock? The 95 score says yes."
- Dramatic one-word sentences used for effect: "Conviction." "Signal." "Locked."
- Any phrasing that sounds like a motivational poster
- "worth taking seriously" / "worth paying attention to" — say what it actually means instead

Tool description openers:
- Never open tweet 2 with a generic description of what Prediction Insiders does

Standalone CTA sentences:
- Never write a sentence whose only purpose is to share the link, like "Check it out at oddsjam.com" or "Find it here: [link]". The link should be embedded naturally in a sentence about the play or the tool.

---

TWEET 1 — Hook styles. Pick a DIFFERENT one each generation:

Style A — Event + label: "[Label] [emoji]\n\n[Team A] vs [Team B], [Bet Type] @ [current price]¢\n\nPrediction Insiders flagged it. Thread below 👇"

Style B — Score first: "[Score]/100.\n\n[Team A] [Bet Type] on Polymarket.\n\nHere's what the insider data says 👇"

Style C — Bet size first: "An insider just put [bet size] on [Team A] [Bet Type] on Polymarket.\n\n[Score]/100 on the Prediction Insiders tool.\n\nBreakdown 👇"

Style D — Slippage/price angle: "[Team A] [Bet Type] is sitting at [current price]¢ right now.\n\nAn insider got in at [entry price]¢. Slippage: [slippage].\n\nPrediction Insiders tool flagged it 👇" (only use if you can read the entry price)

Style E — ROI credibility first: "This insider has a [ROI]% sports ROI across [trades] trades.\n\nThey just went [X]x their normal size on [Team A] [Bet Type].\n\nBreakdown 👇"

Style F — Question/tension: "Why did a Polymarket insider drop [bet size] on [Team A] [Bet Type] at [current price]¢?\n\nPrediction Insiders scored it [Score]/100.\n\nHere's why 👇"

Always end tweet 1 with a hook pointing to the thread. Keep it under 220 characters.

---

TWEET 2 — Requirements:

DO NOT open tweet 2 with a generic description of the Prediction Insiders tool. Instead, open directly with the data or a sharp observation about this specific play. Weave in what the tool does as context mid-tweet, not as an opener.

Cover these 3 things (order can vary, framing must vary each time):
1. Slippage — what it means for this specific play. Positive = market moving with the insider. Negative = you can enter cheaper than the insider did, but their position is underwater.
2. Relative bet size + dollar amount — what the multiplier signals about conviction. 0.5x is a lean, not a full send. 3x+ is max conviction.
3. Sports ROI + trade count — the credibility of this insider. More trades = more meaningful the ROI number.

Close with the score and what it means for this play — not a generic line, but specific to the context of this particular bet.

Include @OddsJam and oddsjam.com/prediction/insiders woven naturally into one of the sentences (e.g. "...flagged by the @OddsJam Prediction Insiders tool: oddsjam.com/prediction/insiders").

---

VIDEO CTA (only include if a video URL is provided):
If the user provides a video URL, include one short line in tweet 2 that links to it. Place it after the data breakdown, before the closing score line. Vary the phrasing each generation — rotate between options like these:
- "Tutorial on how it works: [URL]"
- "Tutorial: [URL]"
- "Full breakdown of how this strategy works: [URL]"
- "How the tool works: [URL]"
- "New to the tool? Quick walkthrough: [URL]"
- "See how we use it: [URL]"

Keep it one line. No extra commentary around it. If no video URL is provided, omit this entirely.

---

STYLE TONES (user may specify one):
- Sharp & Direct: Dense, minimal words. Every sentence is a data point.
- Hype: More energy. Strong verbs. Still data-driven but punchy and urgent.
- Analytical: Add one sentence of "why this matters" context per data point.
- Casual: First-person, conversational. Like texting a friend the play before tip-off.

If not specified, pick the best fit and vary it across generations.

---

LABEL GUIDE — all labels should be Polymarket-focused, not sport-specific:
- Score 92-100: "Polymarket NUKE 💣" or "Polymarket NUKE 🔥" or "Polymarket MAX 🚀"
- Score 80-91: "Polymarket Sharp" or "Polymarket Signal"
- Score 70-79: "Polymarket Play"
- Score below 70: "Polymarket Lean"

If the user provides a custom label, use that instead of this guide.

---

VARIETY RULES — critical for affiliate networks:
Many different accounts will use this tool. Every generation must feel distinct. Actively rotate:
- Tweet 1 hook style (never the same two in a row)
- How you open tweet 2 (never start with a tool description)
- The framing of each data point (same facts, different angle)
- Sentence length, rhythm, and structure throughout

---

OUTPUT FORMAT:
Return ONLY the two tweets separated by this exact separator on its own line:
---TWEET-BREAK---

No preamble, no explanation, no labels like "Tweet 1:" — just the two tweets with the separator between them.`;

app.post('/generate', upload.fields([
  { name: 'toolCard', maxCount: 1 },
  { name: 'slip',     maxCount: 1 }
]), async (req, res) => {
  try {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set.' });

    const client      = new Anthropic({ apiKey });
    const toolFile    = req.files['toolCard']?.[0];
    const slipFile    = req.files['slip']?.[0];
    const customLabel = req.body.label || '';
    const style       = req.body.style || '';
    const positionData = req.body.positionData ? (() => { try { return JSON.parse(req.body.positionData); } catch { return null; } })() : null;

    if (!toolFile) return res.status(400).json({ error: 'Tool card screenshot is required.' });

    const content = [];
    content.push({ type: 'text', text: 'Here is the Prediction Insiders tool card screenshot:' });
    content.push({ type: 'image', source: { type: 'base64', media_type: toolFile.mimetype, data: toolFile.buffer.toString('base64') } });

    if (slipFile) {
      content.push({ type: 'text', text: 'Here is the Polymarket betting slip screenshot:' });
      content.push({ type: 'image', source: { type: 'base64', media_type: slipFile.mimetype, data: slipFile.buffer.toString('base64') } });
    }

    // Inject matched Polymarket position as structured text context
    if (positionData) {
      const entryC  = positionData.avgPrice ? Math.round(positionData.avgPrice * 100) : '?';
      const initVal = positionData.initialValue?.toFixed(2) ?? '?';
      const curVal  = positionData.currentValue?.toFixed(2)  ?? '?';
      const shares  = positionData.size?.toFixed(1)          ?? '?';
      content.push({
        type: 'text',
        text: `User's Polymarket position (matched automatically from the tool card):\n` +
              `Market: ${positionData.market || positionData.title || '?'}\n` +
              `Outcome: ${positionData.outcome || '?'}\n` +
              `Avg entry price: ~${entryC}¢\n` +
              `Position size: $${initVal} (${shares} shares)\n` +
              `Current value: $${curVal}`
      });
    }

    const labelText = customLabel ? `\n\nCustom label to use in Tweet 1: "${customLabel}"` : '';
    const styleText = style       ? `\n\nTone/style for this thread: ${style}` : '';
    const videoText = `\n\nVideo URL to include in Tweet 2: ${VIDEO_URL}`;
    content.push({ type: 'text', text: `Generate the 2-tweet thread from these screenshots.${labelText}${styleText}${videoText}\n\nRemember: do NOT open tweet 2 with a generic tool description. Start with the data. Vary your hook style from previous generations.` });

    const msg = await client.messages.create({
      model:       'claude-sonnet-4-6',
      max_tokens:  1024,
      temperature: 1,
      system:      SYSTEM_PROMPT,
      messages:    [{ role: 'user', content }]
    });

    const parts = msg.content[0].text.split('---TWEET-BREAK---');

    // Silently extract market title + entry price from slip for Winners tracking
    let marketTitle = null, entryPrice = null;
    if (slipFile) {
      try {
        const ex = await client.messages.create({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 60,
          messages: [{ role: 'user', content: [
            { type: 'image', source: { type: 'base64', media_type: slipFile.mimetype, data: slipFile.buffer.toString('base64') } },
            { type: 'text', text: 'From this Polymarket bet slip, reply in EXACTLY this format:\nMARKET: [full market/bet description shown on slip]\nPRICE: [entry price as integer cents, e.g. 66]' }
          ]}]
        });
        const t = ex.content[0].text;
        const mMatch = t.match(/MARKET:\s*(.+)/i);
        const pMatch = t.match(/PRICE:\s*(\d+)/i);
        if (mMatch) marketTitle = mMatch[1].trim();
        if (pMatch) entryPrice  = parseInt(pMatch[1], 10);
      } catch (e) { /* non-fatal */ }
    }

    res.json({ tweet1: parts[0]?.trim() || '', tweet2: parts[1]?.trim() || '', marketTitle, entryPrice });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ── Debug endpoints ───────────────────────────────────────────────────────────
// Test 1: verify OAuth 1.0a signing works at all (calls v2 /users/me)
app.get('/debug/me', async (req, res) => {
  try {
    const r = await twitterFetch('GET', '/users/me');
    const d = await r.json();
    res.json({ status: r.status, data: d });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Test 2: media upload with verbose output
app.get('/debug/media', async (req, res) => {
  try {
    const { token, secret } = getStoredTokens();
    const uploadUrl = 'https://upload.twitter.com/1.1/media/upload.json';

    // Show credential prefixes so we can verify they're correct
    const info = {
      consumer_key_prefix: TWITTER_API_KEY?.slice(0, 8) + '...',
      token_prefix: token?.slice(0, 12) + '...',
      secret_length: secret?.length,
    };

    // Try the upload
    const png1x1 = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwADhQGAWjR9awAAAABJRU5ErkJggg==',
      'base64'
    );
    const authHeader = oauth1Header('POST', uploadUrl, token, secret);

    const formData = new FormData();
    formData.append('media_data', png1x1.toString('base64'));

    const r = await fetch(uploadUrl, {
      method: 'POST',
      headers: { Authorization: authHeader },
      body: formData
    });
    const text = await r.text();
    res.json({ ...info, upload_status: r.status, upload_response: text.slice(0, 500) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Post now ──────────────────────────────────────────────────────────────────
app.post('/post/now', upload.fields([
  { name: 'slip',     maxCount: 1 },
  { name: 'toolCard', maxCount: 1 }
]), async (req, res) => {
  try {
    const { tweet1, tweet2, market_title, entry_price } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets required' });

    const slipFile  = req.files?.['slip']?.[0]     || null;
    const toolFile  = req.files?.['toolCard']?.[0] || null;

    console.log(`[post/now] slip=${slipFile ? slipFile.originalname + ' ' + Math.round(slipFile.size/1024) + 'KB' : 'none'}, tool=${toolFile ? toolFile.originalname + ' ' + Math.round(toolFile.size/1024) + 'KB' : 'none'}`);

    const result = await postThread(tweet1, tweet2, slipFile, toolFile);
    // Save to history so the Winners tab can track it
    db.prepare(`INSERT INTO queue (tweet1, tweet2, scheduled_at, status, posted_at, tweet1_id, tweet2_id, market_title, entry_price)
                VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(tweet1, tweet2, Date.now(), 'posted', Date.now(),
           result.tweet1Id, result.tweet2Id,
           market_title || null, entry_price ? parseInt(entry_price, 10) : null);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Post error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Queue routes ──────────────────────────────────────────────────────────────
app.post('/queue/add', async (req, res) => {
  try {
    const { tweet1, tweet2, market_title, entry_price } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets required' });

    // Schedule 15-20 min after the latest pending item (or from now if queue empty)
    const latest = db.prepare(`SELECT MAX(scheduled_at) as t FROM queue WHERE status='pending'`).get();
    const base   = (latest?.t && latest.t > Date.now()) ? latest.t : Date.now();
    const delay  = (15 + Math.floor(Math.random() * 6)) * 60 * 1000;
    const scheduledAt = base + delay;

    const info = db.prepare('INSERT INTO queue (tweet1, tweet2, scheduled_at, market_title, entry_price) VALUES (?,?,?,?,?)')
      .run(tweet1, tweet2, scheduledAt, market_title || null, entry_price ? parseInt(entry_price, 10) : null);

    res.json({ success: true, id: info.lastInsertRowid, scheduledAt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/queue', (req, res) => {
  const items = db.prepare(`SELECT * FROM queue WHERE status IN ('pending','failed') ORDER BY scheduled_at ASC`).all();
  res.json(items);
});

app.get('/queue/history', (req, res) => {
  const items = db.prepare(`SELECT * FROM queue WHERE status IN ('posted','cancelled') ORDER BY created_at DESC LIMIT 20`).all();
  res.json(items);
});

app.put('/queue/:id', async (req, res) => {
  const { tweet1, tweet2, scheduledAt } = req.body;
  const item = db.prepare(`SELECT * FROM queue WHERE id=? AND status='pending'`).get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found or already posted' });
  db.prepare('UPDATE queue SET tweet1=?, tweet2=?, scheduled_at=? WHERE id=?')
    .run(tweet1 ?? item.tweet1, tweet2 ?? item.tweet2, scheduledAt ?? item.scheduled_at, req.params.id);
  res.json({ success: true });
});

app.delete('/queue/:id', (req, res) => {
  db.prepare(`UPDATE queue SET status='cancelled' WHERE id=? AND status='pending'`).run(req.params.id);
  res.json({ success: true });
});

// ── Queue processor (runs every 60s) ─────────────────────────────────────────
async function processQueue() {
  const due = db.prepare(`SELECT * FROM queue WHERE status='pending' AND scheduled_at <= ?`).all(Date.now());
  for (const item of due) {
    try {
      db.prepare(`UPDATE queue SET status='posting' WHERE id=?`).run(item.id);
      const { tweet1Id, tweet2Id } = await postThread(item.tweet1, item.tweet2);
      db.prepare(`UPDATE queue SET status='posted', posted_at=?, tweet1_id=?, tweet2_id=? WHERE id=?`)
        .run(Date.now(), tweet1Id, tweet2Id, item.id);
      console.log(`[queue] Posted item ${item.id}`);
    } catch (err) {
      console.error(`[queue] Failed item ${item.id}:`, err.message);
      db.prepare(`UPDATE queue SET status='failed', error=? WHERE id=?`).run(err.message, item.id);
    }
  }
}
setInterval(processQueue, 60_000);

// Health check endpoint (for uptime monitors like UptimeRobot)
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

app.listen(PORT, () => console.log(`PI Poster running on port ${PORT}`));
