require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const rateLimit  = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const crypto     = require("crypto");
const path       = require("path");
const cron       = require("node-cron");

const app = express();
const sb  = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.set("trust proxy", 1);
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","OPTIONS"], allowedHeaders: ["Content-Type","Authorization","x-api-key"] }));
app.options("*", cors());
app.use(express.json({ limit: "16mb" }));
app.use(express.static(path.join(__dirname, "dashboard")));

const authLimiter = rateLimit({ windowMs: 60_000, max: 60,  message: { error: "Rate limited" }, standardHeaders: true, legacyHeaders: false });
const apiLimiter  = rateLimit({ windowMs: 60_000, max: 300, message: { error: "Rate limited" }, standardHeaders: true, legacyHeaders: false });

// ── Generators ────────────────────────────────────────────────────────────────
function genKey(prefix = "LUNEX") {
    const seg = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${seg()}-${seg()}-${seg()}`;
}
function genApiKey() { return crypto.randomBytes(32).toString("hex"); }

// ── Auth middleware ───────────────────────────────────────────────────────────
async function requireApiKey(req, res, next) {
    try {
        const key = ((req.headers["authorization"] || "").replace(/^Bearer\s+/i, "").trim()) || req.headers["x-api-key"] || "";
        if (!key) return res.status(401).json({ error: "No API key provided" });
        const { data, error } = await sb.from("owners").select("*").eq("api_key", key).single();
        if (error || !data) return res.status(403).json({ error: "Invalid API key" });
        if (data.expires_at && Math.floor(Date.now() / 1000) > data.expires_at)
            return res.status(403).json({ error: "API key expired" });
        req.owner = data;
        next();
    } catch(e) {
        res.status(500).json({ error: "Auth error: " + e.message });
    }
}

// ── Global error handler ──────────────────────────────────────────────────────
function wrap(fn) {
    return async (req, res, next) => {
        try { await fn(req, res, next); }
        catch(e) {
            console.error("[API Error]", req.method, req.path, e.message);
            if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCRIPT AUTH — Roblox executors hit this
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/auth", authLimiter, wrap(async (req, res) => {
    const { key: userKey, hwid } = req.query;
    const fail = msg => res.set("Content-Type","text/plain").send(`error("Lunex: ${msg}")`);

    if (!userKey || !hwid) return fail("Missing key or hwid");

    const { data: keyRow } = await sb.from("keys")
        .select("*, projects(obfuscated_script, ffa, active, name)")
        .eq("key_string", userKey).single();

    if (!keyRow) return fail("Invalid key");
    if (!keyRow.active) return fail("Key revoked — contact support");
    if (keyRow.expires_at && Math.floor(Date.now() / 1000) > keyRow.expires_at) return fail("Key expired");

    // HWID binding
    if (!keyRow.hwid) {
        const expires_at = keyRow.key_days ? Math.floor(Date.now() / 1000) + keyRow.key_days * 86400 : null;
        await sb.from("keys").update({
            hwid,
            total_executions: 1,
            last_exec: new Date().toISOString(),
            ...(expires_at ? { expires_at } : {})
        }).eq("id", keyRow.id);
    } else if (keyRow.hwid !== hwid) {
        return fail("HWID mismatch — run /resethwid in Discord");
    } else {
        await sb.from("keys").update({
            total_executions: (keyRow.total_executions || 0) + 1,
            last_exec: new Date().toISOString()
        }).eq("id", keyRow.id);
    }

    const project = keyRow.projects;
    if (!project?.active) return fail("Script is offline");
    const script = project.obfuscated_script;
    if (!script?.trim()) return fail("No script uploaded yet");

    res.set("Content-Type", "text/plain").send(script);
}));

// ═══════════════════════════════════════════════════════════════════════════════
// ACCOUNT
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/account", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data } = await sb.from("owners")
        .select("email, plan, created_at, expires_at, obfs_used, obfs_reset_at")
        .eq("id", req.owner.id).single();
    res.json({ success: true, account: data || req.owner });
}));

app.post("/v1/admin/owners", wrap(async (req, res) => {
    if (req.body.admin_secret !== process.env.ADMIN_SECRET)
        return res.status(403).json({ error: "Forbidden" });
    const { email, plan = "elite", days } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    const apiKey  = genApiKey();
    const expires = days ? Math.floor(Date.now() / 1000) + days * 86400 : null;
    const { data, error } = await sb.from("owners").insert({
        email, api_key: apiKey, plan, expires_at: expires, obfs_used: 0
    }).select("id, email, plan").single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, api_key: apiKey, owner: data });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// PROJECTS
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/projects", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data } = await sb.from("projects")
        .select("id, name, ffa, active, script_version, created_at, updated_at")
        .eq("owner_id", req.owner.id)
        .order("created_at", { ascending: false });
    res.json({ success: true, projects: data || [] });
}));

app.post("/v1/projects", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { name, ffa = false } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "Name required" });
    const { count } = await sb.from("projects").select("*", { count: "exact", head: true }).eq("owner_id", req.owner.id);
    const limits = { starter: 3, pro: 10, elite: 50 };
    if ((count || 0) >= (limits[req.owner.plan] || 3))
        return res.status(429).json({ error: `Project limit reached for ${req.owner.plan} plan` });
    const { data, error } = await sb.from("projects").insert({
        owner_id: req.owner.id, name: name.trim(), ffa, active: true, script_version: "0001"
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, project: data });
}));

app.delete("/v1/projects/:id", apiLimiter, requireApiKey, wrap(async (req, res) => {
    await sb.from("projects").delete().eq("id", req.params.id).eq("owner_id", req.owner.id);
    res.json({ success: true });
}));

app.post("/v1/projects/:id/script", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { source, level = "full" } = req.body;
    if (!source?.trim()) return res.status(400).json({ error: "Source required" });
    const { data: proj } = await sb.from("projects").select("*").eq("id", req.params.id).eq("owner_id", req.owner.id).single();
    if (!proj) return res.status(404).json({ error: "Project not found" });
    const newVer = String(parseInt(proj.script_version || "0000") + 1).padStart(4, "0");
    await sb.from("projects").update({
        obfuscated_script: source,
        raw_script: source,
        script_version: newVer,
        updated_at: new Date().toISOString()
    }).eq("id", proj.id);
    const base = process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${process.env.PORT || 8080}`;
    const loader = `script_key="KEY_HERE"\nloadstring(game:HttpGet("${base}/v1/auth?key="..script_key.."&hwid="..game:GetService("RbxAnalyticsService"):GetClientId()))()`;
    res.json({ success: true, version: newVer, loader });
}));

app.post("/v1/projects/:id/toggle", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data: proj } = await sb.from("projects").select("active").eq("id", req.params.id).eq("owner_id", req.owner.id).single();
    if (!proj) return res.status(404).json({ error: "Not found" });
    await sb.from("projects").update({ active: !proj.active }).eq("id", req.params.id);
    res.json({ success: true, active: !proj.active });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// KEYS
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/projects/:id/keys", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { page = 1, limit = 100, search } = req.query;
    const off = (parseInt(page) - 1) * Math.min(parseInt(limit), 200);
    let q = sb.from("keys").select("*", { count: "exact" })
        .eq("project_id", req.params.id)
        .order("created_at", { ascending: false })
        .range(off, off + Math.min(parseInt(limit), 200) - 1);
    if (search) q = q.or(`key_string.ilike.%${search}%,discord_id.ilike.%${search}%,note.ilike.%${search}%`);
    const { data, error, count } = await q;
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, keys: data || [], total: count || 0 });
}));

app.post("/v1/projects/:id/keys", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { amount = 1, key_days, discord_id, note, prefix = "LUNEX" } = req.body;
    if (amount > 500) return res.status(400).json({ error: "Max 500 per request" });
    const keyLimits = { starter: 500, pro: 5000, elite: 50000 };
    const max = keyLimits[req.owner.plan] || 500;
    const { count } = await sb.from("keys").select("*", { count: "exact", head: true }).eq("project_id", req.params.id);
    if ((count || 0) + amount > max)
        return res.status(429).json({ error: `Key limit reached (${max} for ${req.owner.plan})` });
    const rows = Array.from({ length: amount }, () => ({
        project_id: req.params.id,
        key_string: genKey(prefix),
        discord_id: discord_id || null,
        note: note || null,
        active: true,
        key_days: key_days || null,
        expires_at: key_days ? Math.floor(Date.now() / 1000) + key_days * 86400 : null,
        total_executions: 0,
        created_at: new Date().toISOString()
    }));
    const { data, error } = await sb.from("keys").insert(rows).select("key_string");
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, count: data.length, keys: data.map(k => k.key_string) });
}));

app.get("/v1/keys/:key", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data } = await sb.from("keys").select("*").eq("key_string", req.params.key).single();
    if (!data) return res.status(404).json({ error: "Key not found" });
    res.json({ success: true, key: data });
}));

app.post("/v1/keys/:key/resethwid", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data } = await sb.from("keys").update({ hwid: null, last_hwid_reset: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("key_string", req.params.key).select().single();
    if (!data) return res.status(404).json({ error: "Key not found" });
    res.json({ success: true });
}));

app.post("/v1/keys/:key/revoke", apiLimiter, requireApiKey, wrap(async (req, res) => {
    await sb.from("keys").update({ active: false }).eq("key_string", req.params.key);
    res.json({ success: true });
}));

app.post("/v1/keys/:key/unrevoke", apiLimiter, requireApiKey, wrap(async (req, res) => {
    await sb.from("keys").update({ active: true }).eq("key_string", req.params.key);
    res.json({ success: true });
}));

app.post("/v1/keys/:key/extend", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const days = parseInt(req.body.days);
    if (!days || days < 1) return res.status(400).json({ error: "Days required" });
    const { data } = await sb.from("keys").select("expires_at").eq("key_string", req.params.key).single();
    if (!data) return res.status(404).json({ error: "Key not found" });
    const base = data.expires_at ?? Math.floor(Date.now() / 1000);
    await sb.from("keys").update({ expires_at: base + days * 86400 }).eq("key_string", req.params.key);
    res.json({ success: true, new_expiry: base + days * 86400 });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/stats", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data: projs } = await sb.from("projects").select("id").eq("owner_id", req.owner.id);
    const ids = (projs || []).map(p => p.id);
    if (!ids.length) return res.json({ success: true, projects: 0, total_keys: 0, total_executions: 0, plan: req.owner.plan, obfs_used: req.owner.obfs_used || 0 });
    const [keyCnt, execs] = await Promise.all([
        sb.from("keys").select("*", { count: "exact", head: true }).in("project_id", ids),
        sb.from("keys").select("total_executions").in("project_id", ids)
    ]);
    const totalExecs = (execs.data || []).reduce((s, k) => s + (k.total_executions || 0), 0);
    res.json({ success: true, projects: ids.length, total_keys: keyCnt.count || 0, total_executions: totalExecs, plan: req.owner.plan, obfs_used: req.owner.obfs_used || 0 });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL — Discord bot endpoints
// ═══════════════════════════════════════════════════════════════════════════════
function checkInternal(req, res) {
    if (req.body.secret !== process.env.MASTER_SECRET && req.query.secret !== process.env.MASTER_SECRET) {
        res.status(403).json({ error: "Forbidden" });
        return false;
    }
    return true;
}

app.post("/internal/whitelist", wrap(async (req, res) => {
    if (!checkInternal(req, res)) return;
    const { project_id, discord_id, days, note } = req.body;
    const key = genKey();
    const expires_at = days ? Math.floor(Date.now() / 1000) + days * 86400 : null;
    const { data, error } = await sb.from("keys").insert({
        project_id, key_string: key, discord_id, note: note || null,
        active: true, key_days: days || null, expires_at, total_executions: 0,
        created_at: new Date().toISOString()
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, key: data.key_string });
}));

app.post("/internal/resethwid", wrap(async (req, res) => {
    if (!checkInternal(req, res)) return;
    const { discord_id, project_id } = req.body;
    let q = sb.from("keys").update({ hwid: null, last_hwid_reset: new Date().toISOString() }).eq("discord_id", discord_id);
    if (project_id) q = q.eq("project_id", project_id);
    const { data } = await q.select("key_string");
    res.json({ success: true, updated: data?.length || 0 });
}));

app.post("/internal/revoke", wrap(async (req, res) => {
    if (!checkInternal(req, res)) return;
    const { discord_id, project_id } = req.body;
    let q = sb.from("keys").update({ active: false }).eq("discord_id", discord_id);
    if (project_id) q = q.eq("project_id", project_id);
    await q;
    res.json({ success: true });
}));

app.get("/internal/keyinfo", wrap(async (req, res) => {
    if (req.query.secret !== process.env.MASTER_SECRET) return res.status(403).json({ error: "Forbidden" });
    const { data } = await sb.from("keys").select("*").eq("discord_id", req.query.discord_id);
    res.json({ success: true, keys: data || [] });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// CRON JOBS
// ═══════════════════════════════════════════════════════════════════════════════
cron.schedule("*/5 * * * *", async () => {
    const now = Math.floor(Date.now() / 1000);
    await sb.from("keys").update({ active: false }).lt("expires_at", now).eq("active", true).not("expires_at", "is", null);
});
cron.schedule("0 0 1 * *", async () => {
    await sb.from("owners").update({ obfs_used: 0, obfs_reset_at: new Date().toISOString() });
    console.log("[CRON] Monthly obfuscation counters reset");
});

// ═══════════════════════════════════════════════════════════════════════════════
// SERVE DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "dashboard", "index.html"), err => {
        if (err) res.status(500).send("Dashboard not found — ensure dashboard/index.html exists");
    });
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`[Lunex] Server running on port ${PORT}`));
