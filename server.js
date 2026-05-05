const express = require('express');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const Database = require('better-sqlite3');
const session = require('express-session');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
const FormDataLib = require('form-data');
const https = require('https');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database ─────────────────────────────────────────────────────────────────
// DATA_DIR env var → Render persistent disk mount; falls back to local ./data
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Create images subdirectory for storing uploaded images
const imagesDir = path.join(dataDir, 'images');
if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });

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
    market_title TEXT,
    slip_path    TEXT,
    tool_path    TEXT,
    is_quote_tweet INTEGER DEFAULT 0,
    quote_tweet_id TEXT
  );
`);

// Migrate existing queue table if columns missing
const qCols = db.prepare('PRAGMA table_info(queue)').all().map(c => c.name);
if (!qCols.includes('condition_id')) db.exec('ALTER TABLE queue ADD COLUMN condition_id TEXT');
if (!qCols.includes('market_title'))  db.exec('ALTER TABLE queue ADD COLUMN market_title TEXT');
if (!qCols.includes('entry_price'))   db.exec('ALTER TABLE queue ADD COLUMN entry_price INTEGER');
if (!qCols.includes('slip_path'))     db.exec('ALTER TABLE queue ADD COLUMN slip_path TEXT');
if (!qCols.includes('tool_path'))     db.exec('ALTER TABLE queue ADD COLUMN tool_path TEXT');
if (!qCols.includes('is_quote_tweet')) db.exec('ALTER TABLE queue ADD COLUMN is_quote_tweet INTEGER DEFAULT 0');
if (!qCols.includes('quote_tweet_id')) db.exec('ALTER TABLE queue ADD COLUMN quote_tweet_id TEXT');

// Streamer posts table — tracks threads + QTs posted via the Streamer tab
db.exec(`
  CREATE TABLE IF NOT EXISTS streamer_posts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tweet1         TEXT NOT NULL,
    tweet2         TEXT,
    tweet1_id      TEXT,
    tweet2_id      TEXT,
    is_quote_tweet INTEGER DEFAULT 0,
    quote_tweet_id TEXT,
    quote_tweet_url TEXT,
    posted_at      INTEGER DEFAULT (unixepoch() * 1000),
    posted_by      TEXT DEFAULT 'streamer',
    error          TEXT
  );
`);

// QT log table — stores quote tweet text for building suggestion database
db.exec(`
  CREATE TABLE IF NOT EXISTS qt_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    original_tweet_id TEXT NOT NULL,
    original_text  TEXT,
    qt_text        TEXT NOT NULL,
    category       TEXT,
    created_at     INTEGER DEFAULT (unixepoch())
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
// Separate multer instance for video uploads (up to 512MB)
const uploadVideo = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 512 * 1024 * 1024 }
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

// Twitter API v2 GET helper — handles query params in OAuth 1.0a signature
async function twitterGet(endpoint, queryParams = {}) {
  const { token, secret } = getStoredTokens();
  const baseUrl = `https://api.twitter.com/2${endpoint}`;
  // Build full URL with query string
  const qs = new URLSearchParams(queryParams).toString();
  const fullUrl = qs ? `${baseUrl}?${qs}` : baseUrl;
  // OAuth 1.0a: query params must be in signature base string — pass as data
  const authHeader = oauth1Header('GET', baseUrl, token, secret, queryParams);
  const res = await fetch(fullUrl, {
    method: 'GET',
    headers: { Authorization: authHeader }
  });
  return res;
}

// ── Upload media via X API v2 ─────────────────────────────────────────────────
// v1.1 upload.twitter.com was deprecated March 31 2025.
// v2 uses separate endpoints: /initialize, /{id}/append, /{id}/finalize
// (per twitter-api-v2 library source code)

const MEDIA_BASE = 'https://api.x.com/2/media/upload';

// Helper: POST multipart via https.request (for APPEND step)
function postMultipart(urlStr, authHeader, formData) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const req = https.request({
      method: 'POST',
      hostname: u.hostname,
      path: u.pathname,
      headers: { Authorization: authHeader, ...formData.getHeaders() }
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        console.log(`[media] ${u.pathname} ${res.statusCode}:`, body.slice(0, 300));
        if (res.statusCode >= 400) {
          reject(new Error(`${res.statusCode}: ${body.slice(0, 400)}`));
          return;
        }
        try { resolve(body ? JSON.parse(body) : {}); }
        catch { resolve({}); }
      });
    });
    req.on('error', reject);
    formData.pipe(req);
  });
}

// Helper: POST JSON via fetch (for INIT and FINALIZE — v2 requires application/json)
async function postV2JSON(urlStr, authHeader, body) {
  const res = await fetch(urlStr, {
    method: 'POST',
    headers: {
      Authorization: authHeader,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  console.log(`[media] ${new URL(urlStr).pathname} ${res.status}:`, text.slice(0, 300));
  if (!res.ok) throw new Error(`${res.status}: ${text.slice(0, 400)}`);
  return text ? JSON.parse(text) : {};
}

async function uploadMedia(buffer, mimeType) {
  const { token, secret } = getStoredTokens();
  const category = mimeType.startsWith('image/gif') ? 'tweet_gif' : 'tweet_image';
  const ext = mimeType === 'image/png' ? 'png' : mimeType === 'image/gif' ? 'gif' : 'jpg';

  console.log(`[media] Uploading ${mimeType} (${Math.round(buffer.length / 1024)}KB) via v2 chunked`);

  // ── Step 1: INITIALIZE — JSON body ──
  const initUrl  = `${MEDIA_BASE}/initialize`;
  const initAuth = oauth1Header('POST', initUrl, token, secret);
  const initRes  = await postV2JSON(initUrl, initAuth, {
    media_type:     mimeType,
    total_bytes:    buffer.length,
    media_category: category
  });
  const mediaId = initRes.data?.id || initRes.media_id_string || initRes.id;
  if (!mediaId) throw new Error('INIT failed — no media_id: ' + JSON.stringify(initRes));

  // ── Step 2: APPEND — multipart (binary data requires form-data) ──
  const appendUrl  = `${MEDIA_BASE}/${mediaId}/append`;
  const appendAuth = oauth1Header('POST', appendUrl, token, secret);
  const appendFd   = new FormDataLib();
  appendFd.append('segment_index', '0');
  appendFd.append('media', buffer, { filename: `media.${ext}`, contentType: mimeType });
  await postMultipart(appendUrl, appendAuth, appendFd);

  // ── Step 3: FINALIZE — JSON (no body needed, media_id is in URL) ──
  const finUrl  = `${MEDIA_BASE}/${mediaId}/finalize`;
  const finAuth = oauth1Header('POST', finUrl, token, secret);
  await postV2JSON(finUrl, finAuth);

  console.log(`[media] Upload complete: media_id=${mediaId}`);
  return mediaId;
}

// ── Upload video media via X API v2 (chunked + processing poll) ──────────────
// Returns mediaId once processing is complete and ready to attach to a tweet.
// onProgress is an optional callback: (step, detail) => void
const CHUNK_SIZE = 3 * 1024 * 1024; // 3 MB per chunk (v2 append endpoint rejects >~4MB with 413)

async function uploadVideoMedia(buffer, mimeType, onProgress) {
  const { token, secret } = getStoredTokens();
  const ext = mimeType === 'video/mp4' ? 'mp4' : mimeType === 'video/quicktime' ? 'mov' : 'mp4';
  const category = 'tweet_video';
  const log = (step, detail) => {
    console.log(`[video] ${step}: ${detail}`);
    if (onProgress) onProgress(step, detail);
  };

  log('START', `Uploading ${mimeType} (${(buffer.length / (1024 * 1024)).toFixed(1)}MB) via v2 chunked`);

  // ── Step 1: INITIALIZE ──
  const initUrl  = `${MEDIA_BASE}/initialize`;
  const initAuth = oauth1Header('POST', initUrl, token, secret);
  const initRes  = await postV2JSON(initUrl, initAuth, {
    media_type:     mimeType,
    total_bytes:    buffer.length,
    media_category: category
  });
  const mediaId = initRes.data?.id || initRes.media_id_string || initRes.id;
  if (!mediaId) throw new Error('INIT failed — no media_id: ' + JSON.stringify(initRes));
  log('INIT', `media_id=${mediaId}`);

  // ── Step 2: APPEND (chunked — split buffer into 5MB segments) ──
  const totalChunks = Math.ceil(buffer.length / CHUNK_SIZE);
  log('APPEND', `Splitting into ${totalChunks} chunk(s) of up to ${CHUNK_SIZE / (1024*1024)}MB`);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end   = Math.min(start + CHUNK_SIZE, buffer.length);
    const chunk = buffer.slice(start, end);

    const appendUrl  = `${MEDIA_BASE}/${mediaId}/append`;
    const appendAuth = oauth1Header('POST', appendUrl, token, secret);
    const appendFd   = new FormDataLib();
    appendFd.append('segment_index', String(i));
    appendFd.append('media', chunk, { filename: `video_chunk_${i}.${ext}`, contentType: mimeType });
    await postMultipart(appendUrl, appendAuth, appendFd);
    log('APPEND', `Chunk ${i + 1}/${totalChunks} uploaded (${Math.round(chunk.length / 1024)}KB)`);
  }

  // ── Step 3: FINALIZE ──
  const finUrl  = `${MEDIA_BASE}/${mediaId}/finalize`;
  const finAuth = oauth1Header('POST', finUrl, token, secret);
  const finRes  = await postV2JSON(finUrl, finAuth);
  log('FINALIZE', JSON.stringify(finRes).slice(0, 300));

  // ── Step 4: POLL for processing completion (video requires transcoding) ──
  // The finalize response (or subsequent status checks) contain processing_info
  // with state: pending | in_progress | succeeded | failed
  let processingInfo = finRes.processing_info || finRes.data?.processing_info || null;

  if (processingInfo) {
    log('PROCESSING', `Initial state: ${processingInfo.state}`);
    const maxPolls = 60; // up to ~5 minutes of polling
    let polls = 0;

    while (processingInfo && processingInfo.state !== 'succeeded' && processingInfo.state !== 'failed') {
      if (polls++ >= maxPolls) throw new Error('Video processing timed out after 60 polls');

      const waitSec = processingInfo.check_after_secs || 5;
      log('PROCESSING', `State: ${processingInfo.state}, waiting ${waitSec}s (poll ${polls}/${maxPolls})...`);
      await new Promise(r => setTimeout(r, waitSec * 1000));

      // Poll status — GET with query params, OAuth signed
      const statusUrl  = `${MEDIA_BASE}?command=STATUS&media_id=${mediaId}`;
      const statusAuth = oauth1Header('GET', statusUrl, token, secret);
      const statusRes  = await fetch(statusUrl, {
        method: 'GET',
        headers: { Authorization: statusAuth }
      });
      const statusText = await statusRes.text();
      log('STATUS', `${statusRes.status}: ${statusText.slice(0, 300)}`);

      if (!statusRes.ok) throw new Error(`STATUS check failed ${statusRes.status}: ${statusText.slice(0, 400)}`);

      let statusData;
      try { statusData = JSON.parse(statusText); } catch { statusData = {}; }
      processingInfo = statusData.processing_info || statusData.data?.processing_info || null;
    }

    if (processingInfo?.state === 'failed') {
      const errMsg = processingInfo.error?.message || processingInfo.error?.name || 'Unknown processing error';
      throw new Error(`Video processing failed: ${errMsg}`);
    }

    log('PROCESSING', 'Video processing succeeded!');
  } else {
    log('PROCESSING', 'No processing_info returned — video may be ready immediately');
  }

  log('DONE', `Video upload complete: media_id=${mediaId}`);
  return mediaId;
}

// ── Helper: Save image to disk ─────────────────────────────────────────────────
function saveImageToDisk(buffer, mimetype) {
  const ext = mimetype === 'image/png' ? 'png' : mimetype === 'image/gif' ? 'gif' : 'jpg';
  const filename = `${crypto.randomUUID()}.${ext}`;
  const filepath = path.join(imagesDir, filename);
  fs.writeFileSync(filepath, buffer);
  return filename;
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

// ── Post a single quote tweet ──────────────────────────────────────────────────
// tweetText: the quote tweet text
// quoteOfId: the tweet ID to quote
// slipFile / toolFile: optional { buffer, mimetype } objects
// Returns { tweet1Id, mediaErrors[] }
async function postQuoteTweet(tweetText, quoteOfId, slipFile, toolFile) {
  const tweetBody = { text: tweetText };
  const mediaErrors = [];

  if (slipFile?.buffer) {
    try {
      const mediaId = await uploadMedia(slipFile.buffer, slipFile.mimetype);
      tweetBody.media = { media_ids: [mediaId] };
    } catch (e) {
      console.error('[media] Slip upload failed:', e.message);
      mediaErrors.push(`Slip: ${e.message}`);
    }
  }

  if (toolFile?.buffer) {
    try {
      const mediaId = await uploadMedia(toolFile.buffer, toolFile.mimetype);
      if (tweetBody.media) {
        tweetBody.media.media_ids.push(mediaId);
      } else {
        tweetBody.media = { media_ids: [mediaId] };
      }
    } catch (e) {
      console.error('[media] Tool card upload failed:', e.message);
      mediaErrors.push(`Tool card: ${e.message}`);
    }
  }

  // Use URL-in-text method for quote tweets (bypasses tweet-level quote restrictions)
  const tweetUrl = `https://x.com/i/status/${quoteOfId}`;
  tweetBody.text = `${tweetText}\n${tweetUrl}`;
  console.log('[QT] Posting quote tweet via URL method:', tweetUrl);

  const r = await twitterFetch('POST', '/tweets', tweetBody);
  const d = await r.json();
  if (!r.ok) throw new Error(d.detail || d.title || JSON.stringify(d));

  return { tweet1Id: d.data.id, mediaErrors };
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
      console.log(`[winners] Fetched ${positions.length} Polymarket positions for matching`);
    } catch (e) {
      console.error('[winners] Polymarket API failed:', e.message);
      /* continue without position data */
    }

    // Match a DB item to a Polymarket position
    // Strategy: condition_id exact match → market_title fuzzy → tweet1 fuzzy (noise-filtered)
    function matchPosition(item, positions) {
      // 1) Exact match by condition_id (most reliable)
      if (item.condition_id) {
        const exact = positions.find(p =>
          p.conditionId === item.condition_id || p.asset === item.condition_id
        );
        if (exact) return exact;
      }

      const targetPrice = item.entry_price ? item.entry_price / 100 : null;

      function toKeywords(text) {
        return text.toLowerCase().replace(/[^a-z0-9\s.\-]/g, ' ').split(/\s+/).filter(w => w.length > 2);
      }

      function findBest(keywords, threshold) {
        if (!keywords.length) return null;
        let best = null, bestScore = 0;
        for (const pos of positions) {
          const posTitle = (pos.market || pos.title || pos.question || '').toLowerCase();
          const hits = keywords.filter(w => posTitle.includes(w)).length;
          let score = keywords.length ? hits / keywords.length : 0;
          // Price match is a bonus signal, not a hard filter
          if (targetPrice != null && pos.avgPrice != null) {
            const priceDiff = Math.abs(pos.avgPrice - targetPrice);
            if (priceDiff <= 0.03) score += 0.15;
            else if (priceDiff <= 0.08) score += 0.05;
          }
          if (score > bestScore && score >= threshold) { bestScore = score; best = pos; }
        }
        return best;
      }

      // 2) Try market_title first (specific, few keywords, high signal)
      if (item.market_title) {
        const result = findBest(toKeywords(item.market_title), 0.20);
        if (result) return result;
      }

      // 3) Fall back to tweet1 text with noise words removed
      // Tweet text has lots of irrelevant words (polymarket, prediction, insiders, etc.)
      // that dilute the keyword match score — filter them out
      if (item.tweet1) {
        const noise = new Set([
          'the','this','that','with','from','for','and','was','has','had','are','its',
          'polymarket','prediction','insiders','tool','oddsjam','score','insider',
          'thread','below','here','what','says','why','how','breakdown','flagged',
          'right','just','nuke','sharp','signal','play','bet','bets','betting',
          'com','www','full','new','took','into','single','higher','across',
          'opportunity','follow','tutorial','works','youtu','data','price',
          'entry','current','slippage','trades','every','their','they','more'
        ]);
        const keywords = toKeywords(item.tweet1).filter(w => !noise.has(w));
        const result = findBest(keywords, 0.15);
        if (result) return result;
      }

      return null;
    }

    const annotated = posted.map(item => {
      const pos = matchPosition(item, positions);
      let won = false;
      if (pos) {
        if (pos.redeemed && pos.cashPaidOut > 0) won = true;
        else if (pos.curPrice >= 0.99 && pos.size > 0) won = true;
        else if (pos.size > 0 && pos.currentValue >= pos.size * 0.99) won = true;
        else if (pos.winnings > 0) won = true;
      }
      // Debug: log match results for troubleshooting
      console.log(`[winners] Item ${item.id} "${(item.market_title || item.tweet1 || '').slice(0, 40)}..." → ${pos ? `matched "${(pos.market || pos.title || '').slice(0, 40)}" won=${won}` : 'NO MATCH'}`);
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

    // Extract condition_id from position data for exact matching in Winners
    const conditionId = positionData?.conditionId || positionData?.asset || null;

    res.json({ tweet1: parts[0]?.trim() || '', tweet2: parts[1]?.trim() || '', marketTitle, entryPrice, conditionId });
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

    // Show credential prefixes so we can verify they're correct
    const info = {
      consumer_key_prefix: TWITTER_API_KEY?.slice(0, 8) + '...',
      token_prefix: token?.slice(0, 12) + '...',
      secret_length: secret?.length,
    };

    // 50×50 red PNG test image (~141 bytes)
    const png1x1 = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAAAVElEQVR4nO3PsQ0AMAjAMP5/mp7RCHnIHs/O7IXm9wAISDyQWiC1QGqB1AKpBVILpBZILZBaILVAaoHUAqkFUgukFkgtkFogtUBqgdQCqQVS6wzkAbAzdZYM2Ma3AAAAAElFTkSuQmCC',
      'base64'
    );
    // Use same uploadMedia function as real uploads
    try {
      const mediaId = await uploadMedia(png1x1, 'image/png');
      res.json({ ...info, upload_status: 200, media_id_string: mediaId });
    } catch (uploadErr) {
      res.json({ ...info, upload_error: uploadErr.message });
    }
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
    const { tweet1, tweet2, market_title, entry_price, condition_id } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets required' });

    const slipFile  = req.files?.['slip']?.[0]     || null;
    const toolFile  = req.files?.['toolCard']?.[0] || null;

    console.log(`[post/now] slip=${slipFile ? slipFile.originalname + ' ' + Math.round(slipFile.size/1024) + 'KB' : 'none'}, tool=${toolFile ? toolFile.originalname + ' ' + Math.round(toolFile.size/1024) + 'KB' : 'none'}`);

    // Save images to disk if provided
    let slipPath = null, toolPath = null;
    if (slipFile) slipPath = saveImageToDisk(slipFile.buffer, slipFile.mimetype);
    if (toolFile) toolPath = saveImageToDisk(toolFile.buffer, toolFile.mimetype);

    const result = await postThread(tweet1, tweet2, slipFile, toolFile);
    // Save to history so the Winners tab can track it
    db.prepare(`INSERT INTO queue (tweet1, tweet2, scheduled_at, status, posted_at, tweet1_id, tweet2_id, market_title, entry_price, slip_path, tool_path, condition_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(tweet1, tweet2, Date.now(), 'posted', Date.now(),
           result.tweet1Id, result.tweet2Id,
           market_title || null, entry_price ? parseInt(entry_price, 10) : null,
           slipPath, toolPath, condition_id || null);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Post error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Post Quote Tweet immediately ──────────────────────────────────────────────
app.post('/post/qt-now', upload.fields([
  { name: 'slip',     maxCount: 1 },
  { name: 'toolCard', maxCount: 1 }
]), async (req, res) => {
  try {
    const { tweet1, quote_tweet_id, market_title, entry_price } = req.body;
    if (!tweet1 || !quote_tweet_id) return res.status(400).json({ error: 'Tweet text and quote_tweet_id required' });

    const slipFile  = req.files?.['slip']?.[0]     || null;
    const toolFile  = req.files?.['toolCard']?.[0] || null;

    let slipPath = null, toolPath = null;
    if (slipFile) slipPath = saveImageToDisk(slipFile.buffer, slipFile.mimetype);
    if (toolFile) toolPath = saveImageToDisk(toolFile.buffer, toolFile.mimetype);

    const result = await postQuoteTweet(tweet1, quote_tweet_id, slipFile, toolFile);

    // Save to history
    db.prepare(`INSERT INTO queue (tweet1, tweet2, scheduled_at, status, posted_at, tweet1_id, market_title, entry_price, slip_path, tool_path, is_quote_tweet, quote_tweet_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(tweet1, '', Date.now(), 'posted', Date.now(),
           result.tweet1Id,
           market_title || null, entry_price ? parseInt(entry_price, 10) : null,
           slipPath, toolPath, 1, quote_tweet_id);

    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Post QT error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Affiliate QT: @OddsJam feed ─────────────────────────────────────────────
// Cache to avoid hammering the Twitter API (refreshes at most every 5 min)
let ojFeedCache = { data: null, ts: 0 };
const OJ_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Classify a tweet into categories based on content
function classifyTweet(tweet) {
  const text = (tweet.text || '').toLowerCase();
  const cats = [];

  // Huge profit months — look for monthly/daily P&L, large dollar amounts with profit context
  const dollarMatch = text.match(/\$[\d,]+(?:\.\d+)?/g);
  const hasBigDollar = dollarMatch && dollarMatch.some(m => {
    const val = parseFloat(m.replace(/[$,]/g, ''));
    return val >= 1000;
  });
  const profitKeywords = /profit|p&l|p\/l|earned|made|won|up \$|banked|cashed|payout|return|roi|month|daily|week/;
  if (hasBigDollar && profitKeywords.test(text)) cats.push('profit');

  // Huge arbitrage bets — arb-specific language
  const arbKeywords = /arbitrage|arb\b|arbing|risk.?free|guaranteed|sure.?bet|middle|free.?bet/;
  if (arbKeywords.test(text)) cats.push('arbitrage');
  // Also catch arb-adjacent: big dollar + no-risk language
  if (hasBigDollar && /no.?risk|lock|free money|can.?t lose/i.test(text)) cats.push('arbitrage');

  // Affiliate threads — thread indicators + promotional content
  const isThread = /🧵|thread|1\/|part 1|\(1\)|step.by.step|how to|guide|tutorial|walkthrough|breakdown/i.test(text);
  if (isThread) cats.push('thread');

  // Affiliate content — promotional, tool mentions, sign-up language
  const affiliateKeywords = /oddsjam|sign up|free trial|promo|discount|code |use code|link in bio|check out|subscribe|join|tool|software|platform|app\b/;
  if (affiliateKeywords.test(text)) cats.push('affiliate');

  // If nothing matched, mark as 'general'
  if (!cats.length) cats.push('general');

  return cats;
}

// Fetch @OddsJam timeline (last 24h) with engagement metrics
app.get('/api/oddsjam-feed', async (req, res) => {
  try {
    const forceRefresh = req.query.force === '1';

    // Return cache if fresh
    if (!forceRefresh && ojFeedCache.data && (Date.now() - ojFeedCache.ts) < OJ_CACHE_TTL) {
      return res.json(ojFeedCache.data);
    }

    // Step 1: Resolve @OddsJam user ID (cache it)
    if (!ojFeedCache.userId) {
      const userRes = await twitterGet('/users/by/username/OddsJam');
      const userData = await userRes.json();
      if (!userRes.ok || !userData.data?.id) {
        throw new Error('Could not resolve @OddsJam user ID: ' + JSON.stringify(userData));
      }
      ojFeedCache.userId = userData.data.id;
      console.log(`[affiliate] Resolved @OddsJam user ID: ${ojFeedCache.userId}`);
    }

    // Step 2: Fetch recent tweets (max 100, last 24h, exclude replies only)
    // We keep retweets because @OddsJam's affiliate content IS mostly RTs of affiliates
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const timelineRes = await twitterGet(`/users/${ojFeedCache.userId}/tweets`, {
      max_results: '100',
      start_time: since,
      'tweet.fields': 'created_at,public_metrics,referenced_tweets,entities,note_tweet,attachments',
      'expansions': 'attachments.media_keys,referenced_tweets.id',
      'media.fields': 'url,preview_image_url,type,width,height',
      exclude: 'replies'
    });
    const timelineData = await timelineRes.json();

    if (!timelineRes.ok) {
      throw new Error('Timeline fetch failed: ' + JSON.stringify(timelineData));
    }

    // Build media lookup from includes
    const mediaMap = {};
    if (timelineData.includes?.media) {
      for (const m of timelineData.includes.media) {
        mediaMap[m.media_key] = {
          type: m.type,
          url: m.url || m.preview_image_url || null,
          preview_url: m.preview_image_url || m.url || null,
          width: m.width,
          height: m.height
        };
      }
    }

    // Build referenced tweet lookup (for resolving original RT tweet data)
    const refTweetMap = {};
    if (timelineData.includes?.tweets) {
      for (const rt of timelineData.includes.tweets) {
        refTweetMap[rt.id] = rt;
      }
    }

    const tweets = (timelineData.data || []).map(t => {
      const isRetweet = t.referenced_tweets?.some(r => r.type === 'retweeted') || false;
      const retweetRef = isRetweet ? t.referenced_tweets.find(r => r.type === 'retweeted') : null;
      const originalTweet = retweetRef ? refTweetMap[retweetRef.id] : null;

      // For RTs, use the original tweet's metrics (more useful) and resolve its media
      const metrics = (isRetweet && originalTweet?.public_metrics) ? originalTweet.public_metrics : (t.public_metrics || {});
      const engagement = (metrics.like_count || 0) + (metrics.retweet_count || 0) * 2 + (metrics.reply_count || 0);

      // Use note_tweet.text for long tweets if available
      const fullText = t.note_tweet?.text || t.text || '';

      // Resolve media: for RTs, try original tweet's media first
      const srcForMedia = (isRetweet && originalTweet) ? originalTweet : t;
      const mediaKeys = srcForMedia.attachments?.media_keys || t.attachments?.media_keys || [];
      const media = mediaKeys.map(k => mediaMap[k]).filter(Boolean);

      // Extract original author from RT text (e.g. "RT @username: ...")
      let rtAuthor = null;
      if (isRetweet) {
        const authorMatch = fullText.match(/^RT @(\w+):/);
        if (authorMatch) rtAuthor = authorMatch[1];
      }

      return {
        id: t.id,
        text: fullText,
        created_at: t.created_at,
        metrics,
        engagement,
        categories: classifyTweet({ ...t, text: fullText }),
        is_retweet: isRetweet,
        rt_author: rtAuthor,
        original_tweet_id: retweetRef?.id || null,
        is_quote: t.referenced_tweets?.some(r => r.type === 'quoted') || false,
        referenced_tweets: t.referenced_tweets || [],
        urls: t.entities?.urls || [],
        media
      };
    });

    // Sort by engagement (highest first)
    tweets.sort((a, b) => b.engagement - a.engagement);

    const result = { tweets, fetched_at: Date.now(), count: tweets.length };
    ojFeedCache.data = result;
    ojFeedCache.ts = Date.now();
    console.log(`[affiliate] Fetched ${tweets.length} tweets from @OddsJam (last 24h)`);

    res.json(result);
  } catch (err) {
    console.error('[affiliate] Feed error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Log a QT for the suggestion database
app.post('/api/qt-log', (req, res) => {
  try {
    const { original_tweet_id, original_text, qt_text, category } = req.body;
    if (!qt_text || !original_tweet_id) return res.status(400).json({ error: 'qt_text and original_tweet_id required' });
    db.prepare('INSERT INTO qt_log (original_tweet_id, original_text, qt_text, category) VALUES (?,?,?,?)')
      .run(original_tweet_id, original_text || null, qt_text, category || null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get past QT texts for suggestion pre-fills
app.get('/api/qt-suggestions', (req, res) => {
  try {
    const category = req.query.category;
    let rows;
    if (category && category !== 'all') {
      rows = db.prepare('SELECT qt_text, category, created_at FROM qt_log WHERE category = ? ORDER BY created_at DESC LIMIT 20').all(category);
    } else {
      rows = db.prepare('SELECT qt_text, category, created_at FROM qt_log ORDER BY created_at DESC LIMIT 20').all();
    }
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// AI-powered QT suggestion — uses past QTs + original tweet to draft text
app.post('/api/qt-suggest-ai', async (req, res) => {
  try {
    const { original_text, category, rt_author } = req.body;
    if (!original_text) return res.status(400).json({ error: 'original_text required' });

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set' });

    // Fetch recent QTs from the log to learn the user's style
    const pastQTs = db.prepare(
      'SELECT original_text, qt_text, category FROM qt_log ORDER BY created_at DESC LIMIT 30'
    ).all();

    let styleExamples = '';
    if (pastQTs.length > 0) {
      styleExamples = '\n\nHere are examples of quote tweets I\'ve written before (learn my tone, style, and patterns):\n' +
        pastQTs.map((q, i) => `${i + 1}. Original: "${q.original_text || 'N/A'}"\n   My QT: "${q.qt_text}"`).join('\n');
    }

    const client = new Anthropic({ apiKey });
    const msg = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 600,
      temperature: 1,
      messages: [{
        role: 'user',
        content: `You are helping me write a quote tweet for a sports betting affiliate post.

Original tweet (from @${rt_author || 'OddsJam'}):
"${original_text}"

Category: ${category || 'general'}
${styleExamples}

Write 3 different quote tweet options. Each should:
- Be under 240 characters
- Feel natural, not salesy or corny
- Reference OddsJam or the tool naturally if it fits
- Match my past writing style if examples were provided
- NEVER use em dashes (—)
- No generic hype like "Let's go!" or "This is huge!"
- Be conversational and authentic

Return ONLY 3 options, one per line, numbered 1-3. Nothing else.`
      }]
    });

    const text = msg.content[0].text.trim();
    const suggestions = text.split('\n')
      .map(l => l.replace(/^\d+[\.\)]\s*/, '').trim())
      .filter(l => l.length > 0 && l.length <= 280);

    res.json({ suggestions });
  } catch (err) {
    console.error('[ai-suggest] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Analytics — post volume, engagement, and metrics over time
app.get('/api/analytics', async (req, res) => {
  try {
    const range = parseInt(req.query.days) || 30;
    const sinceTs = Math.floor(Date.now() / 1000) - (range * 86400);

    // All posted items in range
    const posted = db.prepare(
      `SELECT id, tweet1, tweet2, posted_at, tweet1_id, tweet2_id, is_quote_tweet, quote_tweet_id, market_title, created_at
       FROM queue WHERE status='posted' AND posted_at > ? ORDER BY posted_at DESC`
    ).all(sinceTs * 1000); // posted_at is in milliseconds

    // Split into PI tweets vs Affiliate QTs
    const piTweets = posted.filter(p => !p.is_quote_tweet);
    const affQTs = posted.filter(p => p.is_quote_tweet);

    // QT log stats
    const qtLogCount = db.prepare(
      'SELECT COUNT(*) as cnt FROM qt_log WHERE created_at > ?'
    ).get(sinceTs).cnt;

    // Daily breakdown
    const dailyMap = {};
    for (const p of posted) {
      const day = new Date(p.posted_at).toISOString().slice(0, 10);
      if (!dailyMap[day]) dailyMap[day] = { date: day, pi: 0, affiliate: 0, total: 0 };
      if (p.is_quote_tweet) dailyMap[day].affiliate++;
      else dailyMap[day].pi++;
      dailyMap[day].total++;
    }
    const daily = Object.values(dailyMap).sort((a, b) => a.date.localeCompare(b.date));

    // Try to fetch engagement metrics from Twitter for recent tweets
    let tweetMetrics = [];
    const tweetIds = posted
      .map(p => p.tweet1_id)
      .filter(Boolean)
      .slice(0, 100); // API limit

    if (tweetIds.length > 0) {
      try {
        const batchSize = 100;
        for (let i = 0; i < tweetIds.length; i += batchSize) {
          const batch = tweetIds.slice(i, i + batchSize);
          const metricsRes = await twitterGet('/tweets', {
            ids: batch.join(','),
            'tweet.fields': 'public_metrics,created_at'
          });
          const metricsData = await metricsRes.json();
          if (metricsData.data) {
            tweetMetrics.push(...metricsData.data);
          }
        }
      } catch (e) {
        console.error('[analytics] Metrics fetch error:', e.message);
      }
    }

    // Aggregate metrics
    let totalImpressions = 0, totalLikes = 0, totalRetweets = 0, totalReplies = 0;
    const metricsById = {};
    for (const t of tweetMetrics) {
      const m = t.public_metrics || {};
      totalImpressions += m.impression_count || 0;
      totalLikes += m.like_count || 0;
      totalRetweets += m.retweet_count || 0;
      totalReplies += m.reply_count || 0;
      metricsById[t.id] = m;
    }

    // Build per-tweet detail list with metrics
    const tweetDetails = posted.map(p => {
      const m = metricsById[p.tweet1_id] || {};
      return {
        id: p.id,
        tweet1_id: p.tweet1_id,
        text: p.tweet1.substring(0, 100) + (p.tweet1.length > 100 ? '...' : ''),
        type: p.is_quote_tweet ? 'affiliate_qt' : 'pi_tweet',
        posted_at: p.posted_at,
        market_title: p.market_title,
        impressions: m.impression_count || 0,
        likes: m.like_count || 0,
        retweets: m.retweet_count || 0,
        replies: m.reply_count || 0,
        engagement: (m.like_count || 0) + (m.retweet_count || 0) * 2 + (m.reply_count || 0)
      };
    });

    // Sort by engagement for "top performers"
    const topPerformers = [...tweetDetails].sort((a, b) => b.engagement - a.engagement).slice(0, 10);

    res.json({
      range_days: range,
      summary: {
        total_posts: posted.length,
        pi_tweets: piTweets.length,
        affiliate_qts: affQTs.length,
        qt_texts_logged: qtLogCount,
        total_impressions: totalImpressions,
        total_likes: totalLikes,
        total_retweets: totalRetweets,
        total_replies: totalReplies
      },
      daily,
      top_performers: topPerformers,
      tweets: tweetDetails
    });
  } catch (err) {
    console.error('[analytics] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Serve stored images ───────────────────────────────────────────────────────
app.get('/api/images/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    // Sanitize filename to prevent directory traversal
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    const filepath = path.join(imagesDir, filename);
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({ error: 'Image not found' });
    }
    res.sendFile(filepath);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Queue routes ──────────────────────────────────────────────────────────────
// Add a regular thread to queue (multipart: slip + toolCard images)
app.post('/queue/add', upload.fields([
  { name: 'slip',     maxCount: 1 },
  { name: 'toolCard', maxCount: 1 }
]), async (req, res) => {
  try {
    const { tweet1, tweet2, market_title, entry_price, condition_id } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets required' });

    const slipFile  = req.files?.['slip']?.[0]     || null;
    const toolFile  = req.files?.['toolCard']?.[0] || null;

    // Save images to disk if provided
    let slipPath = null, toolPath = null;
    if (slipFile) slipPath = saveImageToDisk(slipFile.buffer, slipFile.mimetype);
    if (toolFile) toolPath = saveImageToDisk(toolFile.buffer, toolFile.mimetype);

    // Schedule 15-20 min after the latest pending item (or from now if queue empty)
    const latest = db.prepare(`SELECT MAX(scheduled_at) as t FROM queue WHERE status='pending'`).get();
    const base   = (latest?.t && latest.t > Date.now()) ? latest.t : Date.now();
    const delay  = (15 + Math.floor(Math.random() * 6)) * 60 * 1000;
    const scheduledAt = base + delay;

    const info = db.prepare('INSERT INTO queue (tweet1, tweet2, scheduled_at, market_title, entry_price, slip_path, tool_path, is_quote_tweet, condition_id) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(tweet1, tweet2, scheduledAt, market_title || null, entry_price ? parseInt(entry_price, 10) : null, slipPath, toolPath, 0, condition_id || null);

    res.json({ success: true, id: info.lastInsertRowid, scheduledAt });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Affiliate QT scheduling helper ───────────────────────────────────────────
// Finds the next available slot in the preferred windows: 7-9 AM CT or 7-10 PM CT
// Slots are ~1 hour apart. CT = UTC-6 (CST) or UTC-5 (CDT).
function getNextAffiliateSlot() {
  // Determine CT offset (CDT Mar-Nov = UTC-5, CST Nov-Mar = UTC-6)
  // Simple DST check: 2nd Sunday of March to 1st Sunday of November
  const now = new Date();
  const year = now.getUTCFullYear();
  const mar2nd = new Date(Date.UTC(year, 2, 8)); // March 8 at latest
  const marchSunday = new Date(Date.UTC(year, 2, 8 + (7 - mar2nd.getUTCDay()) % 7, 7)); // 2nd Sunday March at 2AM CT
  const nov1st = new Date(Date.UTC(year, 10, 1)); // Nov 1 at latest
  const novSunday = new Date(Date.UTC(year, 10, 1 + (7 - nov1st.getUTCDay()) % 7, 7)); // 1st Sunday Nov at 2AM CT
  const isDST = now >= marchSunday && now < novSunday;
  const ctOffsetHours = isDST ? -5 : -6;

  // Get current hour in CT
  function toCT(date) {
    return new Date(date.getTime() + ctOffsetHours * 60 * 60 * 1000);
  }
  function fromCT(ctDate) {
    return new Date(ctDate.getTime() - ctOffsetHours * 60 * 60 * 1000);
  }

  // Get already-scheduled affiliate QTs (pending) to avoid overlap
  const pendingSlots = db.prepare(`SELECT scheduled_at FROM queue WHERE status='pending' ORDER BY scheduled_at ASC`).all()
    .map(r => r.scheduled_at);

  // Build candidate slots starting from now, looking ahead up to 48 hours
  const candidates = [];
  const startCT = toCT(now);

  for (let dayOffset = 0; dayOffset <= 2; dayOffset++) {
    const dayCT = new Date(startCT);
    dayCT.setUTCDate(dayCT.getUTCDate() + dayOffset);

    // Morning window: 7:00 - 9:00 AM CT (slots at 7:00, 8:00)
    for (let h = 7; h <= 8; h++) {
      const slotCT = new Date(dayCT);
      slotCT.setUTCHours(h, Math.floor(Math.random() * 30), 0, 0); // random 0-29 min offset
      const slotUTC = fromCT(slotCT);
      if (slotUTC.getTime() > now.getTime()) candidates.push(slotUTC.getTime());
    }

    // Evening window: 7:00 - 10:00 PM CT (slots at 19:00, 20:00, 21:00)
    for (let h = 19; h <= 21; h++) {
      const slotCT = new Date(dayCT);
      slotCT.setUTCHours(h, Math.floor(Math.random() * 30), 0, 0);
      const slotUTC = fromCT(slotCT);
      if (slotUTC.getTime() > now.getTime()) candidates.push(slotUTC.getTime());
    }
  }

  // Filter out slots that are too close to already-scheduled items (within 45 min)
  const MIN_GAP = 45 * 60 * 1000;
  const available = candidates.filter(slot => {
    return !pendingSlots.some(existing => Math.abs(existing - slot) < MIN_GAP);
  });

  if (available.length === 0) {
    // Fallback: just use 1 hour after last pending, or 1 hour from now
    const latest = pendingSlots.length ? pendingSlots[pendingSlots.length - 1] : now.getTime();
    return Math.max(latest, now.getTime()) + 60 * 60 * 1000;
  }

  // Return the earliest available slot
  return available[0];
}

// Add a quote tweet to queue
app.post('/queue/add-qt', upload.fields([
  { name: 'slip',     maxCount: 1 },
  { name: 'toolCard', maxCount: 1 }
]), async (req, res) => {
  try {
    const { tweet1, quote_tweet_id, market_title, entry_price, affiliate_schedule } = req.body;
    if (!tweet1 || !quote_tweet_id) return res.status(400).json({ error: 'Tweet text and quote_tweet_id required' });

    const slipFile  = req.files?.['slip']?.[0]     || null;
    const toolFile  = req.files?.['toolCard']?.[0] || null;

    // Save images to disk if provided
    let slipPath = null, toolPath = null;
    if (slipFile) slipPath = saveImageToDisk(slipFile.buffer, slipFile.mimetype);
    if (toolFile) toolPath = saveImageToDisk(toolFile.buffer, toolFile.mimetype);

    let scheduledAt;
    if (affiliate_schedule) {
      // Affiliate QT scheduling: 7-9 AM CT or 7-10 PM CT, ~1hr apart
      scheduledAt = getNextAffiliateSlot();
    } else {
      // Default: 15-20 min after the latest pending item (or from now)
      const latest = db.prepare(`SELECT MAX(scheduled_at) as t FROM queue WHERE status='pending'`).get();
      const base   = (latest?.t && latest.t > Date.now()) ? latest.t : Date.now();
      const delay  = (15 + Math.floor(Math.random() * 6)) * 60 * 1000;
      scheduledAt = base + delay;
    }

    const info = db.prepare('INSERT INTO queue (tweet1, tweet2, scheduled_at, market_title, entry_price, slip_path, tool_path, is_quote_tweet, quote_tweet_id) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(tweet1, '', scheduledAt, market_title || null, entry_price ? parseInt(entry_price, 10) : null, slipPath, toolPath, 1, quote_tweet_id);

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

      // Load images from disk if paths are stored
      let slipFile = null, toolFile = null;
      if (item.slip_path && fs.existsSync(path.join(imagesDir, item.slip_path))) {
        const buffer = fs.readFileSync(path.join(imagesDir, item.slip_path));
        const ext = path.extname(item.slip_path).toLowerCase();
        const mimetype = ext === '.png' ? 'image/png' : ext === '.gif' ? 'image/gif' : 'image/jpeg';
        slipFile = { buffer, mimetype };
      }
      if (item.tool_path && fs.existsSync(path.join(imagesDir, item.tool_path))) {
        const buffer = fs.readFileSync(path.join(imagesDir, item.tool_path));
        const ext = path.extname(item.tool_path).toLowerCase();
        const mimetype = ext === '.png' ? 'image/png' : ext === '.gif' ? 'image/gif' : 'image/jpeg';
        toolFile = { buffer, mimetype };
      }

      let result;
      if (item.is_quote_tweet) {
        // Post as a quote tweet
        result = await postQuoteTweet(item.tweet1, item.quote_tweet_id, slipFile, toolFile);
        db.prepare(`UPDATE queue SET status='posted', posted_at=?, tweet1_id=? WHERE id=?`)
          .run(Date.now(), result.tweet1Id, item.id);
      } else {
        // Post as a regular thread
        const { tweet1Id, tweet2Id } = await postThread(item.tweet1, item.tweet2, slipFile, toolFile);
        db.prepare(`UPDATE queue SET status='posted', posted_at=?, tweet1_id=?, tweet2_id=? WHERE id=?`)
          .run(Date.now(), tweet1Id, tweet2Id, item.id);
      }

      console.log(`[queue] Posted item ${item.id}`);
    } catch (err) {
      console.error(`[queue] Failed item ${item.id}:`, err.message);
      db.prepare(`UPDATE queue SET status='failed', error=? WHERE id=?`).run(err.message, item.id);
    }
  }
}
setInterval(processQueue, 60_000);

// ── Video test endpoint ──────────────────────────────────────────────────────
// Accepts a video file + optional tweet text, uploads via v2 chunked + processing poll,
// then posts a tweet with the video attached.
app.post('/test/video-tweet', uploadVideo.single('video'), async (req, res) => {
  const steps = []; // accumulate progress for the response
  try {
    const file = req.file;
    const tweetText = req.body.text || 'Video upload test via PI Poster';
    if (!file) return res.status(400).json({ error: 'No video file provided' });

    const allowedTypes = ['video/mp4', 'video/quicktime', 'video/x-m4v', 'video/webm'];
    if (!allowedTypes.includes(file.mimetype)) {
      return res.status(400).json({ error: `Unsupported video type: ${file.mimetype}. Use MP4, MOV, M4V, or WebM.` });
    }

    // 512MB max per Twitter docs
    if (file.buffer.length > 512 * 1024 * 1024) {
      return res.status(400).json({ error: 'Video exceeds 512MB limit' });
    }

    steps.push({ step: 'RECEIVED', detail: `${file.originalname} (${(file.buffer.length / (1024*1024)).toFixed(1)}MB, ${file.mimetype})` });

    const mediaId = await uploadVideoMedia(file.buffer, file.mimetype, (step, detail) => {
      steps.push({ step, detail });
    });

    steps.push({ step: 'TWEETING', detail: `Posting tweet with media_id=${mediaId}` });

    // Post tweet with video attached
    const tweetBody = {
      text: tweetText,
      media: { media_ids: [mediaId] }
    };
    const r = await twitterFetch('POST', '/tweets', tweetBody);
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || d.title || JSON.stringify(d));

    const tweetId = d.data.id;
    steps.push({ step: 'SUCCESS', detail: `Tweet posted! ID: ${tweetId} — https://x.com/EVBettors/status/${tweetId}` });

    res.json({ success: true, tweetId, tweetUrl: `https://x.com/EVBettors/status/${tweetId}`, steps });
  } catch (err) {
    console.error('[video-test] Error:', err);
    steps.push({ step: 'ERROR', detail: err.message });
    res.status(500).json({ success: false, error: err.message, steps });
  }
});

// ── Streamer endpoints ────────────────────────────────────────────────────────

// Post a 2-tweet thread from the Streamer tab (with optional images on each tweet)
app.post('/streamer/post-thread', upload.fields([
  { name: 'image1', maxCount: 1 },
  { name: 'image2', maxCount: 1 }
]), async (req, res) => {
  try {
    const { tweet1, tweet2 } = req.body;
    if (!tweet1 || !tweet2) return res.status(400).json({ error: 'Both tweets are required' });

    const img1 = req.files?.['image1']?.[0] || null;
    const img2 = req.files?.['image2']?.[0] || null;

    console.log(`[streamer] Thread: img1=${img1 ? Math.round(img1.size/1024) + 'KB' : 'none'}, img2=${img2 ? Math.round(img2.size/1024) + 'KB' : 'none'}`);

    // Reuse the existing postThread function (slip→tweet1, toolCard→tweet2)
    const result = await postThread(tweet1, tweet2, img1, img2);

    // Save to streamer_posts
    db.prepare(`INSERT INTO streamer_posts (tweet1, tweet2, tweet1_id, tweet2_id, posted_at)
                VALUES (?,?,?,?,?)`)
      .run(tweet1, tweet2, result.tweet1Id, result.tweet2Id, Date.now());

    res.json({ success: true, ...result });
  } catch (err) {
    console.error('[streamer] Thread post error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Post a quote tweet from the Streamer tab
app.post('/streamer/post-qt', upload.fields([
  { name: 'image1', maxCount: 1 }
]), async (req, res) => {
  try {
    const { tweet1, quote_tweet_id, quote_tweet_url } = req.body;
    if (!tweet1) return res.status(400).json({ error: 'Tweet text is required' });

    // Resolve the quote target — either a direct ID or extract from a URL
    let qtId = quote_tweet_id || null;
    const qtUrl = quote_tweet_url || null;

    if (!qtId && qtUrl) {
      // Extract tweet ID from URL like https://x.com/user/status/123456 or https://twitter.com/user/status/123456
      const urlMatch = qtUrl.match(/(?:twitter\.com|x\.com)\/\w+\/status\/(\d+)/);
      if (urlMatch) qtId = urlMatch[1];
    }

    if (!qtId) return res.status(400).json({ error: 'No valid tweet ID or URL provided' });

    const img1 = req.files?.['image1']?.[0] || null;

    // Use URL-in-text method (proven reliable, bypasses quote restrictions)
    const tweetUrl = `https://x.com/i/status/${qtId}`;
    const tweetBody = { text: `${tweet1}\n${tweetUrl}` };

    if (img1?.buffer) {
      try {
        const mediaId = await uploadMedia(img1.buffer, img1.mimetype);
        tweetBody.media = { media_ids: [mediaId] };
      } catch (e) {
        console.error('[streamer] Image upload failed:', e.message);
      }
    }

    console.log(`[streamer] QT posting, target: ${qtId}`);
    const r = await twitterFetch('POST', '/tweets', tweetBody);
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || d.title || JSON.stringify(d));

    // Save to streamer_posts
    db.prepare(`INSERT INTO streamer_posts (tweet1, tweet1_id, is_quote_tweet, quote_tweet_id, quote_tweet_url, posted_at)
                VALUES (?,?,?,?,?,?)`)
      .run(tweet1, d.data.id, 1, qtId, qtUrl || null, Date.now());

    res.json({ success: true, tweet1Id: d.data.id });
  } catch (err) {
    console.error('[streamer] QT post error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get the streamer posts feed
app.get('/streamer/feed', (req, res) => {
  try {
    const posts = db.prepare(
      'SELECT * FROM streamer_posts ORDER BY posted_at DESC LIMIT 100'
    ).all();
    res.json({ posts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check endpoint (for uptime monitors like UptimeRobot)
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

app.listen(PORT, () => console.log(`PI Poster running on port ${PORT}`));
