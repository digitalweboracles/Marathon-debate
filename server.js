'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ------- config (overridable on Railway via Variables) -------
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'gwr-admin-2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const RSVP_FILE = path.join(DATA_DIR, 'rsvps.json');
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

// ------- data store -------
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(RSVP_FILE)) fs.writeFileSync(RSVP_FILE, '[]');

function readRsvps() {
  try { return JSON.parse(fs.readFileSync(RSVP_FILE, 'utf8')); }
  catch { return []; }
}
function writeRsvps(list) {
  fs.writeFileSync(RSVP_FILE, JSON.stringify(list, null, 2));
}
function sha256(v) {
  return crypto.createHash('sha256').update(String(v)).digest('hex');
}

// in-memory session tokens (lost on redeploy, fine for admin access)
const sessions = new Map();
function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now());
  return token;
}
function isAuthed(req) {
  const t = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  const exp = sessions.get(t);
  if (!exp) return false;
  if (Date.now() - exp > SESSION_TTL_MS) { sessions.delete(t); return false; }
  return true;
}

// ------- middleware -------
app.use(express.json({ limit: '100kb' }));
app.disable('x-powered-by');

// ------- public static site (index.html + assets only) -------
// We serve an explicit whitelist so source files (server.js, package.json)
// and the RSVP data file under data/ are never exposed publicly.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.use('/assets', express.static(path.join(__dirname, 'assets'), { maxAge: '1h' }));

// ------- RSVP API -------
app.post('/api/rsvp', (req, res) => {
  const { name, role, contact } = req.body || {};
  if (!name || !role || !contact) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  const clean = (s) => String(s || '').trim().slice(0, 200);
  const entry = {
    id: crypto.randomBytes(8).toString('hex'),
    name: clean(name),
    role: clean(role),
    contact: clean(contact),
    createdAt: new Date().toISOString()
  };
  if (!entry.name || !entry.role || !entry.contact) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  const list = readRsvps();
  list.push(entry);
  writeRsvps(list);
  res.status(201).json({ ok: true, id: entry.id });
});

// ------- admin auth -------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const a = Buffer.from(sha256(username || ''), 'hex');
  const b = Buffer.from(sha256(ADMIN_USER), 'hex');
  const c = Buffer.from(sha256(password || ''), 'hex');
  const d = Buffer.from(sha256(ADMIN_PASS), 'hex');
  const okUser = a.length === b.length && crypto.timingSafeEqual(a, b);
  const okPass = c.length === d.length && crypto.timingSafeEqual(c, d);
  if (okUser && okPass) {
    return res.json({ token: createSession() });
  }
  return res.status(401).json({ error: 'Invalid credentials.' });
});

// ------- admin data (auth required) -------
const apiAuth = (req, res, next) => isAuthed(req) ? next() : res.status(401).json({ error: 'Unauthorized. Please log in.' });

app.get('/api/rsvps', apiAuth, (req, res) => {
  const list = readRsvps();
  const fmt = list.map(r => ({
    ...r,
    createdAt: new Date(r.createdAt).toLocaleString('en-GB', {
      timeZone: 'Africa/Lagos', dateStyle: 'medium', timeStyle: 'short'
    })
  }));
  res.json(fmt);
});

app.get('/api/rsvps/export', apiAuth, (req, res) => {
  const list = readRsvps();
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = 'Name,Role,Contact,Submitted (WAT)';
  const rows = list.map(r => [
    esc(r.name),
    esc(r.role),
    esc(r.contact),
    esc(new Date(r.createdAt).toLocaleString('en-GB', {
      timeZone: 'Africa/Lagos', dateStyle: 'medium', timeStyle: 'short'
    }))
  ].join(','));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="rsvps.csv"');
  res.send([header, ...rows].join('\n'));
});

app.delete('/api/rsvps/:id', apiAuth, (req, res) => {
  const list = readRsvps();
  const next = list.filter(r => r.id !== req.params.id);
  if (next.length === list.length) {
    return res.status(404).json({ error: 'Not found.' });
  }
  writeRsvps(next);
  res.json({ ok: true });
});

// ------- admin dashboard page -------
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});