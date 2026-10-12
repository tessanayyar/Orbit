const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "orbit.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK(length(body) <= 2000),
  mood_card TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS likes (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK(length(body) <= 1000),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS saved_posts (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS stories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK(length(body) <= 500),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK(length(title) <= 120),
  event_date TEXT NOT NULL,
  event_time TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK(length(body) <= 2000),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const SQLiteStore = SQLiteStoreFactory(session);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false })); // inline scripts/styles are used by the supplied prototype
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false });
const postLimiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false });

function cleanString(value, max, field) {
  if (typeof value !== "string") throw Object.assign(new Error(`${field} must be text`), { status: 400 });
  const result = value.trim();
  if (!result || result.length > max) throw Object.assign(new Error(`${field} must be 1–${max} characters`), { status: 400 });
  return result;
}
function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT id, username, display_name AS displayName, created_at AS createdAt FROM users WHERE id = ?").get(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Sign in to do that." });
  req.user = user;
  next();
}
function handleErrors(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
function postShape(row, viewerId) {
  return {
    id: row.id, body: row.body, moodCard: row.mood_card || null, createdAt: row.created_at,
    author: { id: row.user_id, username: row.username, displayName: row.display_name },
    likes: row.like_count || 0, comments: row.comment_count || 0,
    likedByMe: Boolean(row.liked_by_me), savedByMe: Boolean(row.saved_by_me)
  };
}

app.get("/api/health", (req, res) => res.json({ ok: true, service: "orbit-api", time: new Date().toISOString() }));

app.post("/api/auth/register", authLimiter, handleErrors(async (req, res) => {
  const username = cleanString(String(req.body.username || "").toLowerCase(), 24, "username");
  const displayName = cleanString(req.body.displayName || username, 40, "displayName");
  const password = cleanString(req.body.password || "", 128, "password");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3–24 characters: letters, numbers, underscores." });
  if (password.length < 10) return res.status(400).json({ error: "Use a password with at least 10 characters." });
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const result = db.prepare("INSERT INTO users (username, display_name, password_hash) VALUES (?, ?, ?)").run(username, displayName, passwordHash);
    req.session.userId = Number(result.lastInsertRowid);
    res.status(201).json({ user: currentUser(req) });
  } catch (e) {
    if (String(e.code).startsWith("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "That username is already taken." });
    throw e;
  }
}));

app.post("/api/auth/login", authLimiter, handleErrors(async (req, res) => {
  const username = cleanString(String(req.body.username || "").toLowerCase(), 24, "username");
  const password = cleanString(req.body.password || "", 128, "password");
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Username or password is incorrect." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start a session." });
    req.session.userId = user.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Could not save session." });
      res.json({ user: currentUser(req) });
    });
  });
}));
app.post("/api/auth/logout", (req, res) => req.session.destroy(err => {
  if (err) return res.status(500).json({ error: "Could not sign out." });
  res.clearCookie("connect.sid", { httpOnly: true, sameSite: "lax", secure: NODE_ENV === "production" });
  res.json({ ok: true });
}));
app.get("/api/auth/me", (req, res) => res.json({ user: currentUser(req) }));

app.get("/api/posts", (req, res) => {
  const viewerId = req.session.userId || 0;
  const limit = Math.min(Math.max(Number(req.query.limit) || 30, 1), 100);
  const before = Number(req.query.before) || Number.MAX_SAFE_INTEGER;
  const rows = db.prepare(`
    SELECT p.*, u.username, u.display_name,
      (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
      EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = ?) AS liked_by_me,
      EXISTS(SELECT 1 FROM saved_posts s WHERE s.post_id = p.id AND s.user_id = ?) AS saved_by_me
    FROM posts p JOIN users u ON u.id = p.user_id
    WHERE p.id < ? ORDER BY p.id DESC LIMIT ?
  `).all(viewerId, viewerId, before, limit);
  res.json({ posts: rows.map(row => postShape(row, viewerId)) });
});
app.post("/api/posts", requireAuth, postLimiter, (req, res) => {
  let body, moodCard = null;
  try { body = cleanString(req.body.body, 2000, "body"); if (req.body.moodCard) moodCard = cleanString(req.body.moodCard, 180, "moodCard"); }
  catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const result = db.prepare("INSERT INTO posts (user_id, body, mood_card) VALUES (?, ?, ?)").run(req.user.id, body, moodCard);
  res.status(201).json({ id: Number(result.lastInsertRowid), message: "Post created." });
});
app.delete("/api/posts/:id", requireAuth, (req, res) => {
  const post = db.prepare("SELECT user_id FROM posts WHERE id = ?").get(Number(req.params.id));
  if (!post) return res.status(404).json({ error: "Post not found." });
  if (post.user_id !== req.user.id) return res.status(403).json({ error: "You can only delete your own posts." });
  db.prepare("DELETE FROM posts WHERE id = ?").run(Number(req.params.id));
  res.json({ ok: true });
});

app.post("/api/posts/:id/like", requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  if (!db.prepare("SELECT id FROM posts WHERE id = ?").get(postId)) return res.status(404).json({ error: "Post not found." });
  const existing = db.prepare("SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?").get(req.user.id, postId);
  if (existing) db.prepare("DELETE FROM likes WHERE user_id = ? AND post_id = ?").run(req.user.id, postId);
  else db.prepare("INSERT INTO likes (user_id, post_id) VALUES (?, ?)").run(req.user.id, postId);
  const count = db.prepare("SELECT COUNT(*) AS count FROM likes WHERE post_id = ?").get(postId).count;
  res.json({ liked: !existing, likes: count });
});
app.get("/api/posts/:id/comments", (req, res) => {
  const comments = db.prepare(`SELECT c.id, c.body, c.created_at AS createdAt, u.username, u.display_name AS displayName
    FROM comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.id ASC`).all(Number(req.params.id));
  res.json({ comments });
});
app.post("/api/posts/:id/comments", requireAuth, (req, res) => {
  let body;
  try { body = cleanString(req.body.body, 1000, "body"); } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const postId = Number(req.params.id);
  if (!db.prepare("SELECT id FROM posts WHERE id = ?").get(postId)) return res.status(404).json({ error: "Post not found." });
  const result = db.prepare("INSERT INTO comments (user_id, post_id, body) VALUES (?, ?, ?)").run(req.user.id, postId, body);
  res.status(201).json({ id: Number(result.lastInsertRowid), message: "Reply added." });
});
app.get("/api/saved", requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT p.*, u.username, u.display_name,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS like_count,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
    EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = ?) AS liked_by_me,
    1 AS saved_by_me
    FROM saved_posts s JOIN posts p ON p.id = s.post_id JOIN users u ON u.id = p.user_id
    WHERE s.user_id = ? ORDER BY s.created_at DESC`).all(req.user.id, req.user.id);
  res.json({ posts: rows.map(row => postShape(row, req.user.id)) });
});
app.post("/api/posts/:id/save", requireAuth, (req, res) => {
  const postId = Number(req.params.id);
  if (!db.prepare("SELECT id FROM posts WHERE id = ?").get(postId)) return res.status(404).json({ error: "Post not found." });
  const existing = db.prepare("SELECT 1 FROM saved_posts WHERE user_id = ? AND post_id = ?").get(req.user.id, postId);
  if (existing) db.prepare("DELETE FROM saved_posts WHERE user_id = ? AND post_id = ?").run(req.user.id, postId);
  else db.prepare("INSERT INTO saved_posts (user_id, post_id) VALUES (?, ?)").run(req.user.id, postId);
  res.json({ saved: !existing });
});

app.get("/api/stories", (req, res) => {
  db.prepare("DELETE FROM stories WHERE expires_at <= datetime('now')").run();
  const stories = db.prepare(`SELECT s.id, s.body, s.created_at AS createdAt, s.expires_at AS expiresAt,
    u.username, u.display_name AS displayName FROM stories s JOIN users u ON u.id = s.user_id
    WHERE s.expires_at > datetime('now') ORDER BY s.id DESC LIMIT 100`).all();
  res.json({ stories });
});
app.post("/api/stories", requireAuth, (req, res) => {
  let body;
  try { body = cleanString(req.body.body, 500, "body"); } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const result = db.prepare("INSERT INTO stories (user_id, body, expires_at) VALUES (?, ?, datetime('now', '+24 hours'))").run(req.user.id, body);
  res.status(201).json({ id: Number(result.lastInsertRowid), expiresInHours: 24 });
});

app.get("/api/events", (req, res) => {
  const events = db.prepare(`SELECT e.id, e.title, e.event_date AS date, e.event_time AS time,
    u.username, u.display_name AS displayName FROM events e JOIN users u ON u.id=e.user_id
    WHERE e.event_date >= date('now') ORDER BY e.event_date, e.event_time LIMIT 100`).all();
  res.json({ events });
});
app.post("/api/events", requireAuth, (req, res) => {
  let title;
  try { title = cleanString(req.body.title, 120, "title"); } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const date = String(req.body.date || "");
  const time = req.body.time ? String(req.body.time) : null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date))) return res.status(400).json({ error: "Use a valid date in YYYY-MM-DD format." });
  if (time && !/^\d{2}:\d{2}$/.test(time)) return res.status(400).json({ error: "Use a valid time in HH:MM format." });
  const result = db.prepare("INSERT INTO events (user_id, title, event_date, event_time) VALUES (?, ?, ?, ?)").run(req.user.id, title, date, time);
  res.status(201).json({ id: Number(result.lastInsertRowid), message: "Event created." });
});

app.get("/api/users", requireAuth, (req, res) => {
  const users = db.prepare("SELECT id, username, display_name AS displayName FROM users WHERE id != ? ORDER BY display_name LIMIT 100").all(req.user.id);
  res.json({ users });
});
app.get("/api/messages/:userId", requireAuth, (req, res) => {
  const otherId = Number(req.params.userId);
  const messages = db.prepare(`SELECT id, sender_id AS senderId, recipient_id AS recipientId, body, created_at AS createdAt
    FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
    ORDER BY id DESC LIMIT 100`).all(req.user.id, otherId, otherId, req.user.id).reverse();
  res.json({ messages });
});
app.post("/api/messages/:userId", requireAuth, (req, res) => {
  const otherId = Number(req.params.userId);
  if (!db.prepare("SELECT id FROM users WHERE id = ?").get(otherId)) return res.status(404).json({ error: "User not found." });
  let body;
  try { body = cleanString(req.body.body, 2000, "body"); } catch (e) { return res.status(e.status || 400).json({ error: e.message }); }
  const result = db.prepare("INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)").run(req.user.id, otherId, body);
  res.status(201).json({ id: Number(result.lastInsertRowid), message: "Message sent." });
});

app.use("/api", (req, res) => res.status(404).json({ error: "API route not found." }));
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: NODE_ENV === "production" ? "Something went wrong." : err.message || "Internal server error." });
});
app.listen(PORT, () => console.log(`Orbit is running at http://localhost:${PORT}`));
