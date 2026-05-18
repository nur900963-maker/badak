const express = require("express");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-admin-secret");
  if (req.method === "OPTIONS") { res.sendStatus(204); return; }
  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function query(sql, params) {
  const client = await pool.connect();
  try { return await client.query(sql, params); }
  finally { client.release(); }
}

query(`CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  expired_at BIGINT,
  is_vip BOOLEAN NOT NULL DEFAULT false
)`).then(() => console.log("DB ready")).catch(e => console.error("DB init error:", e.message));

app.get("/", (_req, res) => res.json({ status: "ok", app: "BADAK WA API" }));
app.get("/api/healthz", (_req, res) => res.json({ status: "ok" }));

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ ok: false, error: "USERNAME_AND_PASSWORD_REQUIRED" });
    const r = await query("SELECT * FROM users WHERE username=$1 LIMIT 1", [username.toLowerCase().trim()]);
    if (r.rows.length === 0) return res.status(401).json({ ok: false, error: "USER_NOT_FOUND" });
    const u = r.rows[0];
    if (u.password !== password) return res.status(401).json({ ok: false, error: "WRONG_PASSWORD" });
    if (u.expired_at && Date.now() > Number(u.expired_at)) return res.status(401).json({ ok: false, error: "EXPIRED" });
    res.json({ ok: true, user: { username: u.username, expiredAt: u.expired_at ? Number(u.expired_at) : null, isVip: u.is_vip } });
  } catch (e) { console.error(e.message); res.status(500).json({ ok: false, error: "SERVER_ERROR" }); }
});

app.use("/api/admin", (req, res, next) => {
  if (!process.env.ADMIN_SECRET || req.headers["x-admin-secret"] !== process.env.ADMIN_SECRET)
    return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
  next();
});

app.get("/api/admin/users", async (_req, res) => {
  try {
    const r = await query("SELECT id, username, expired_at, is_vip FROM users ORDER BY id", []);
    res.json({ ok: true, users: r.rows.map(u => ({ id: u.id, username: u.username, expiredAt: u.expired_at ? Number(u.expired_at) : null, isVip: u.is_vip })) });
  } catch (e) { res.status(500).json({ ok: false, error: "SERVER_ERROR" }); }
});

app.post("/api/admin/users", async (req, res) => {
  try {
    const { username, password, durationDays, isVip } = req.body || {};
    if (!username || !password) return res.status(400).json({ ok: false, error: "USERNAME_AND_PASSWORD_REQUIRED" });
    const expiredAt = (!durationDays || durationDays <= 0) ? null : Date.now() + durationDays * 86400000;
    await query("INSERT INTO users (username, password, expired_at, is_vip) VALUES ($1,$2,$3,$4)",
      [username.toLowerCase().trim(), password, expiredAt, isVip ?? false]);
    res.json({ ok: true, user: { username: username.toLowerCase().trim(), expiredAt, isVip: isVip ?? false } });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ ok: false, error: "USERNAME_TAKEN" });
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

app.delete("/api/admin/users/:username", async (req, res) => {
  try {
    await query("DELETE FROM users WHERE username=$1", [req.params.username.toLowerCase()]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: "SERVER_ERROR" }); }
});

app.patch("/api/admin/users/:username/extend", async (req, res) => {
  try {
    const { durationDays } = req.body || {};
    if (!durationDays || durationDays <= 0) return res.status(400).json({ ok: false, error: "INVALID_DURATION" });
    const r = await query("SELECT * FROM users WHERE username=$1 LIMIT 1", [req.params.username.toLowerCase()]);
    if (r.rows.length === 0) return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });
    const u = r.rows[0];
    const base = u.expired_at && Number(u.expired_at) > Date.now() ? Number(u.expired_at) : Date.now();
    const newExpiry = base + durationDays * 86400000;
    await query("UPDATE users SET expired_at=$1 WHERE username=$2", [newExpiry, req.params.username.toLowerCase()]);
    res.json({ ok: true, user: { username: u.username, expiredAt: newExpiry, isVip: u.is_vip } });
  } catch (e) { res.status(500).json({ ok: false, error: "SERVER_ERROR" }); }
});

app.patch("/api/admin/users/:username/password", async (req, res) => {
  try {
    const { newPassword } = req.body || {};
    if (!newPassword) return res.status(400).json({ ok: false, error: "PASSWORD_REQUIRED" });
    await query("UPDATE users SET password=$1 WHERE username=$2", [newPassword, req.params.username.toLowerCase()]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: "SERVER_ERROR" }); }
});

app.patch("/api/admin/users/:username", async (req, res) => {
  try {
    const { password, durationDays, isVip } = req.body || {};
    const sets = []; const vals = [];
    if (password !== undefined) { sets.push(`password=$${sets.length+1}`); vals.push(password); }
    if (isVip !== undefined) { sets.push(`is_vip=$${sets.length+1}`); vals.push(isVip); }
    if (durationDays !== undefined) {
      const exp = (!durationDays || durationDays <= 0) ? null : Date.now() + durationDays * 86400000;
      sets.push(`expired_at=$${sets.length+1}`); vals.push(exp);
    }
    if (sets.length === 0) return res.status(400).json({ ok: false, error: "NOTHING_TO_UPDATE" });
    vals.push(req.params.username.toLowerCase());
    await query(`UPDATE users SET ${sets.join(",")} WHERE username=$${vals.length}`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: "SERVER_ERROR" }); }
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`BADAK WA API running on port ${PORT}`));
}
