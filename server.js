const express = require('express');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const Database = require('better-sqlite3');
const session = require('express-session');
const crypto = require('crypto');
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
    created_at   INTEGER DEFAULT (unixepoch())
  );
`);

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
const TWITTER_CLIENT_ID     = process.env.TWITTER_CLIENT_ID;
const TWITTER_CLIENT_SECRET = process.env.TWITTER_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || 'https://evbettors-tweet-tool.onrender.com/auth/twitter/callback';
const SCOPES = ['tweet.read', 'tweet.write', 'users.read', 'offline.access'];

// ── PKCE helpers ──────────────────────────────────────────────────────────────
function generateVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}
function generateChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ── Twitter API helper ────────────────────────────────────────────────────────
async function twitterFetch(method, endpoint, accessToken, body) {
  const res = await fetch(`https://api.twitter.com/2${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  return res;
}

// ── Token management ──────────────────────────────────────────────────────────
async function refreshToken() {
  const auth = db.prepare('SELECT * FROM auth WHERE id = 1').get();
  if (!auth?.refresh_token) throw new Error('Not authenticated');

  const params = new URLSearchParams({
    grant_type:    'refresh_token',
    refresh_token: auth.refresh_token,
    client_id:     TWITTER_CLIENT_ID
  });
  const credentials = Buffer.from(`${TWITTER_CLIENT_ID}:${TWITTER_CLIENT_SECRET}`).toString('base64');
  const res = await fetch('https://api.twitter.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      Authorization:   `Basic ${credentials}`
    },
    body: params
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || 'Token refresh failed');

  const expiry = Date.now() + data.expires_in * 1000;
  db.prepare('UPDATE auth SET access_token=?, refresh_token=?, token_expiry=? WHERE id=1')
    .run(data.access_token, data.refresh_token || auth.refresh_token, expiry);

  return data.access_token;
}

async function getAccessToken() {
  const auth = db.prepare('SELECT * FROM auth WHERE id = 1').get();
  if (!auth) throw new Error('Not connected. Click "Connect Twitter" first.');
  if (Date.now() > auth.token_expiry - 60_000) return refreshToken();
  return auth.access_token;
}

// ── Post a thread ─────────────────────────────────────────────────────────────
async function postThread(tweet1, tweet2) {
  const token = await getAccessToken();

  const r1 = await twitterFetch('POST', '/tweets', token, { text: tweet1 });
  const d1 = await r1.json();
  if (!r1.ok) throw new Error(d1.detail || d1.title || JSON.stringify(d1));

  const tweet1Id = d1.data.id;

  const r2 = await twitterFetch('POST', '/tweets', token, {
    text: tweet2,
    reply: { in_reply_to_tweet_id: tweet1Id }
  });
  const d2 = await r2.json();
  if (!r2.ok) throw new Error(d2.detail || d2.title || JSON.stringify(d2));

  return { tweet1Id, tweet2Id: d2.data.id };
}

// ── OAuth routes ──────────────────────────────────────────────────────────────
app.get('/auth/twitter', (req, res) => {
  const verifier  = generateVerifier();
  const challenge = generateChallenge(verifier);
  const state     = crypto.randomBytes(16).toString('hex');

  req.session.codeVerifier = verifier;
  req.session.oauthState   = state;

  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             TWITTER_CLIENT_ID,
    redirect_uri:          CALLBACK_URL,
    scope:                 SCOPES.join(' '),
    state,
    code_challenge:        challenge,
    code_challenge_method: 'S256'
  });
  res.redirect(`https://twitter.com/i/oauth2/authorize?${params}`);
});

app.get('/auth/twitter/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`/?error=${encodeURIComponent(error)}`);
  if (state !== req.session.oauthState) return res.status(400).send('Invalid state');

  try {
    const params = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      redirect_uri:  CALLBACK_URL,
      code_verifier: req.session.codeVerifier,
      client_id:     TWITTER_CLIENT_ID
    });
    const credentials = Buffer.from(`${TWITTER_CLIENT_ID}:${TWITTER_CLIENT_SECRET}`).toString('base64');
    const res2 = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization:  `Basic ${credentials}`
      },
      body: params
    });
    const data = await res2.json();
    if (!res2.ok) throw new Error(data.error_description || 'Token exchange failed');

    const expiry = Date.now() + data.expires_in * 1000;

    // Fetch user info
    const userRes  = await twitterFetch('GET', '/users/me', data.access_token);
    const userData = await userRes.json();
    const username = userData.data?.username || 'unknown';
    const userId   = userData.data?.id       || 'unknown';

    const existing = db.prepare('SELECT id FROM auth WHERE id = 1').get();
    if (existing) {
      db.prepare('UPDATE auth SET access_token=?,refresh_token=?,token_expiry=?,user_id=?,username=? WHERE id=1')
        .run(data.access_token, data.refresh_token, expiry, userId, username);
    } else {
      db.prepare('INSERT INTO auth (id,access_token,refresh_token,token_expiry,user_id,username) VALUES (1,?,?,?,?,?)')
        .run(data.access_token, data.refresh_token, expiry, userId, username);
    }
    res.redirect('/?connected=1');
  } catch (err) {
    console.error('OAuth error:', err);
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

// ── AI generation (same prompt as affiliate tool) ─────────────────────────────
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

Derive insider entry price if not directly visible: current price minus slippage amount. Only include the entry price if you can read or reasonably derive it — do not fabricate it.

---

HARD RULES — never break these:
- NEVER use em dashes (the — character). Zero exceptions, zero tolerance. Rewrite using a comma, colon, period, or line break.
- Never fabricate or estimate numbers. Use only what is visible in the screenshots.
- Keep tweet 1 under 220 characters.
- Tweet 2 must include all 3 data points: bet size and relative size, slippage context, sports ROI.
- End tweet 2 with the score out of 100 and what that score signals.
- When referencing the tool with a link, the URL must always follow a colon. Correct: "the @OddsJam Prediction Insiders tool: oddsjam.com/prediction/insiders". Never "tool at oddsjam.com/...".

BANNED PHRASES AND SENTENCE STRUCTURES:
- "That's not noise" / "Worth tracking" / "Worth watching" / "Game changer" / "This is huge"
- "The money is moving" / "Follow the smart money"
- "The data is screaming" / "The data doesn't lie" / any dramatic data personification
- The "not X, it's Y" contrast structure in all forms
- Rhetorical self-answering sentences: "Is this a lock? The score says yes."
- Dramatic one-word sentences: "Conviction." "Signal." "Locked."
- "worth taking seriously" / "worth paying attention to"
- Never open tweet 2 with a generic tool description
- Never write a standalone CTA sentence whose only purpose is sharing the link

---

TWEET 1 — Hook styles. Rotate between these, pick a different one each generation:

Style A — Event + label: "[Label] [emoji]\n\n[Team A] vs [Team B], [Bet Type] @ [current price]c\n\nPrediction Insiders flagged it. Thread below 👇"
Style B — Score first: "[Score]/100.\n\n[Team A] [Bet Type] on Polymarket.\n\nHere's what the insider data says 👇"
Style C — Bet size first: "An insider just put [bet size] on [Team A] [Bet Type] on Polymarket.\n\n[Score]/100 on the Prediction Insiders tool.\n\nBreakdown 👇"
Style D — Slippage angle: "[Team A] [Bet Type] is at [current price]c.\n\nInsider got in at [entry price]c. Slippage: [slippage].\n\nPrediction Insiders flagged it 👇"
Style E — ROI first: "This insider has a [ROI]% sports ROI across [trades] trades.\n\nThey just went [X]x their normal size on [Team A] [Bet Type].\n\nBreakdown 👇"
Style F — Question: "Why did an insider drop [bet size] on [Team A] [Bet Type] at [current price]c?\n\nPrediction Insiders scored it [Score]/100.\n\nHere's why 👇"

---

TWEET 2 — open directly with the data, not a tool description. Cover these 3 things (order can vary):
1. Slippage: what it means for this specific play
2. Relative bet size + dollar amount: what the multiplier signals about conviction
3. Sports ROI + trade count: the credibility of this insider

Close with the score and what it means for this play.
Include @OddsJam and oddsjam.com/prediction/insiders woven naturally into one sentence.

---

LABEL GUIDE:
- Score 92-100: "Polymarket NUKE 💣" or "Polymarket NUKE 🔥" or "Polymarket MAX 🚀"
- Score 80-91: "Polymarket Sharp" or "Polymarket Signal"
- Score 70-79: "Polymarket Play"
- Score below 70: "Polymarket Lean"
If the user provides a custom label, use that instead.

STYLE TONES (user may specify): Sharp & Direct / Hype / Analytical / Casual
If not specified, pick the best fit and vary it.

---

OUTPUT FORMAT:
Return ONLY the two tweets separated by this exact separator on its own line:
---TWEET-BREAK---

No preamble, no explanation, no labels — just the two tweets with the separator between them.`;

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

    if (!toolFile) return res.status(400).json({ error: 'Tool card screenshot is required.' });

    const content = [];
    content.push({ type: 'text', text: 'Here is the Prediction Insiders tool card screenshot:' });
    content.push({ type: 'image', source: { type: 'base64', media_type: toolFile.mimetype, data: toolFile.buffer.toString('base64') } });

    if (slipFile) {
      content.push({ type: 'text', text: 'Here is the Polymarket betting slip screenshot:' });
      content.push({ type: 'image', source: { type: 'base64', media_type: slipFile.mimetype, data: slipFile.buffer.toString('base64') } });
    }

    const labelText = customLabel ? `\n\nCustom label: "${customLabel}"` : '';
    const styleText = style       ? `\n\nTone: ${style}` : '';
    content.push({ type: 'text', text: `Generate the 2-tweet thread.${labelText}${styleText}\n\nDo NOT open tweet 2 with a generic tool description. Start with the data. Vary your hook style.` });

    const msg = await client.messages.create({
      model:       'claude-sonnet-4-6',
      max_tokens:  1024,
      temperature: 1,
      system:      SYSTEM_PROMPT,
      messages:    [{ role: 'user', content }]
    });

    const parts = msg.content[0].text.split('---TWEET-BREAK---');
    res.json({ tweet1: parts[0]?.trim() || '', tweet2: parts[1]?.trim() || '' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ── Post now ──────────────────────────────────────────────────────────────────
app.post('/post/now', async (req, res) => {
  try {
    const { tweet1, tweet2 } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets required' });
    const result = await postThread(tweet1, tweet2);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Post error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Queue routes ──────────────────────────────────────────────────────────────
app.post('/queue/add', async (req, res) => {
  try {
    const { tweet1, tweet2 } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets required' });

    // Schedule 15-20 min after the latest pending item (or from now if queue empty)
    const latest = db.prepare(`SELECT MAX(scheduled_at) as t FROM queue WHERE status='pending'`).get();
    const base   = (latest?.t && latest.t > Date.now()) ? latest.t : Date.now();
    const delay  = (15 + Math.floor(Math.random() * 6)) * 60 * 1000;
    const scheduledAt = base + delay;

    const info = db.prepare('INSERT INTO queue (tweet1, tweet2, scheduled_at) VALUES (?,?,?)')
      .run(tweet1, tweet2, scheduledAt);

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

app.listen(PORT, () => console.log(`PI Poster running on port ${PORT}`));
