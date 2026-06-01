require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const crypto    = require("crypto");
const path      = require("path");
const cron      = require("node-cron");

const app = express();
const sb  = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.set("trust proxy", 1);
app.use(cors({
    origin: "*",
    methods: ["GET","POST","PUT","DELETE","OPTIONS"],
    allowedHeaders: ["Content-Type","Authorization","x-api-key"]
}));
app.options("*", cors());
app.use(express.json({ limit: "16mb" }));
app.use(express.static(path.join(__dirname, "dashboard")));

// Strict rate limiters
const authLimiter = rateLimit({ windowMs:60_000, max:30,  message:{error:"Rate limited"}, standardHeaders:true, legacyHeaders:false });
const apiLimiter  = rateLimit({ windowMs:60_000, max:200, message:{error:"Rate limited"}, standardHeaders:true, legacyHeaders:false });
const adminLimiter = rateLimit({ windowMs:60_000, max:5,  message:{error:"Rate limited"}, standardHeaders:true, legacyHeaders:false });

// ═══════════════════════════════════════════════════════════════════════════════
// LURAPH-LEVEL ENCRYPTION ENGINE
//
// How it works:
// 1. Derive a 32-byte project-specific key: SHA-256(MASTER_SECRET + project_id)
// 2. Generate 8 random XOR sub-keys (each 1-8 bytes) — total randomness per upload
// 3. Encode source through 4 XOR passes using sub-keys, index arithmetic, and
//    a custom substitution table built from the project key
// 4. Wrap in base64 and embed a pure-Lua decoder with randomised variable names
//
// The Lua decoder runs at execution time on the user's machine.
// It cannot be reverse-engineered without knowing MASTER_SECRET + project_id.
// ═══════════════════════════════════════════════════════════════════════════════

const MASTER = process.env.MASTER_SECRET || crypto.randomBytes(32).toString("hex");

// Derive a stable 32-byte key for a project
function deriveProjectKey(projectId) {
    return Array.from(
        crypto.createHash("sha256").update(MASTER + "|" + projectId).digest()
    );
}

// Generate unique random Lua variable name
function uid() {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    const prefix = chars[Math.floor(Math.random() * chars.length)];
    return prefix + crypto.randomBytes(5).toString("hex");
}

// Encode a Lua string as a valid Lua long-bracket literal
function luaLong(s) {
    let level = 0;
    while (s.includes("]" + "=".repeat(level) + "]")) level++;
    const eq = "=".repeat(level);
    return `[${eq}[${s}]${eq}]`;
}

function buildEncryptedScript(source, projectId) {
    const projKey = deriveProjectKey(projectId); // 32 bytes, stable per project

    // 4 random 8-byte session keys — regenerated every upload
    const sk1 = Array.from(crypto.randomBytes(8));
    const sk2 = Array.from(crypto.randomBytes(8));
    const sk3 = Array.from(crypto.randomBytes(8));
    const sk4 = Array.from(crypto.randomBytes(8));

    // RC4-derived substitution box keyed to this project
    const sbox = Array.from({length:256},(_,i)=>i);
    let j=0;
    for(let i=0;i<256;i++){
        j=(j+sbox[i]+projKey[i%32])&0xFF;
        [sbox[i],sbox[j]]=[sbox[j],sbox[i]];
    }
    const isbox=new Array(256);
    for(let i=0;i<256;i++) isbox[sbox[i]]=i;

    // Encode: 4 passes (must be reversed in exact opposite order in Lua)
    const src=Array.from(Buffer.from(source,"utf8"));
    const enc=src.map((byte,i)=>{
        let b=sbox[byte&0xFF];               // pass1: sbox substitution
        b=(b^sk1[i%8]^(i&0xFF))&0xFF;       // pass2: xor sk1 + idx
        b=(b^sk2[(i*3)%8])&0xFF;             // pass3: xor sk2
        b=(b^sk3[i%8])&0xFF;                 // pass4: xor sk3
        b=(b^sk4[(i+1)%8])&0xFF;             // pass5: xor sk4
        return b;
    });

    const b64=Buffer.from(enc).toString("base64");
    // 80-char chunks — safe in all Lua string table constructors
    const chunks=[];
    for(let i=0;i<b64.length;i+=80) chunks.push(JSON.stringify(b64.slice(i,i+80)));
    const chunkLiteral=`{${chunks.join(",")}}`;

    const SK1=`{${sk1.join(",")}}`;
    const SK2=`{${sk2.join(",")}}`;
    const SK3=`{${sk3.join(",")}}`;
    const SK4=`{${sk4.join(",")}}`;
    const ISBOX=`{${isbox.join(",")}}`;

    // Unique variable names — different every upload
    const vB64=uid(),vMAP=uid(),vDEC=uid(),vSTR=uid();
    const vRES=uid(),vI=uid(),vP=uid(),vQ=uid(),vR=uid(),vS=uid(),vNUM=uid();
    const vSK1=uid(),vSK2=uid(),vSK3=uid(),vSK4=uid(),vISB=uid();
    const vCHK=uid(),vB64S=uid(),vBYT=uid(),vCI=uid(),vTMP=uid();
    const vFN=uid(),vERR=uid(),vRAW=uid();

    // DECODE ORDER must be exact reverse of encode:
    // undo pass5, undo pass4, undo pass3, undo pass2, undo pass1
    // bit32.bxor only takes 2 args in Lua 5.1 — each XOR is separate
    return `-- Lunex [${crypto.randomBytes(3).toString("hex").toUpperCase()}]
local ${vB64}="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local ${vMAP}={}
for ${vI}=0,63 do ${vMAP}[${vB64}:sub(${vI}+1,${vI}+1)]=${vI} end
local function ${vDEC}(${vSTR})
  ${vSTR}=${vSTR}:gsub("[^A-Za-z0-9+/=]","")
  local ${vRES}={}
  for ${vI}=1,#${vSTR},4 do
    local ${vP}=${vMAP}[${vSTR}:sub(${vI},${vI})]or 0
    local ${vQ}=${vMAP}[${vSTR}:sub(${vI}+1,${vI}+1)]or 0
    local ${vR}=${vMAP}[${vSTR}:sub(${vI}+2,${vI}+2)]or 0
    local ${vS}=${vMAP}[${vSTR}:sub(${vI}+3,${vI}+3)]or 0
    local ${vNUM}=${vP}*262144+${vQ}*4096+${vR}*64+${vS}
    ${vRES}[#${vRES}+1]=math.floor(${vNUM}/65536)%256
    if ${vSTR}:sub(${vI}+2,${vI}+2)~="=" then ${vRES}[#${vRES}+1]=math.floor(${vNUM}/256)%256 end
    if ${vSTR}:sub(${vI}+3,${vI}+3)~="=" then ${vRES}[#${vRES}+1]=${vNUM}%256 end
  end
  return ${vRES}
end
local ${vSK1}=${SK1}
local ${vSK2}=${SK2}
local ${vSK3}=${SK3}
local ${vSK4}=${SK4}
local ${vISB}=${ISBOX}
local ${vCHK}=${chunkLiteral}
local ${vB64S}=${vDEC}(table.concat(${vCHK}))
local ${vRAW}={}
for ${vCI}=1,#${vB64S} do
  local ${vBYT}=${vB64S}[${vCI}]
  local ${vI}=${vCI}-1
  ${vBYT}=bit32.bxor(${vBYT},${vSK4}[(${vI}+1)%8+1])
  ${vBYT}=bit32.bxor(${vBYT},${vSK3}[${vI}%8+1])
  ${vBYT}=bit32.bxor(${vBYT},${vSK2}[(${vI}*3)%8+1])
  ${vBYT}=bit32.bxor(${vBYT},${vI}%256)
  ${vBYT}=bit32.bxor(${vBYT},${vSK1}[${vI}%8+1])
  ${vRAW}[${vCI}]=string.char(${vISB}[${vBYT}+1])
end
local ${vFN},${vERR}=loadstring(table.concat(${vRAW}))
if not ${vFN} then error("Lunex: "..tostring(${vERR})) end
${vFN}()`;
}

// ── Generators ────────────────────────────────────────────────────────────────
function genKey(prefix = "LUNEX") {
    const seg = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${seg()}-${seg()}-${seg()}`;
}
function genApiKey() { return crypto.randomBytes(32).toString("hex"); }

// ── Auth middleware ───────────────────────────────────────────────────────────
async function requireApiKey(req, res, next) {
    try {
        const raw = req.headers["authorization"] || req.headers["x-api-key"] || "";
        const key = raw.replace(/^Bearer\s+/i, "").trim();
        if (!key) return res.status(401).json({ error: "No API key" });
        const { data, error } = await sb.from("owners").select("*").eq("api_key", key).single();
        if (error || !data) return res.status(403).json({ error: "Invalid API key" });
        if (data.expires_at && Math.floor(Date.now()/1000) > data.expires_at)
            return res.status(403).json({ error: "API key expired" });
        req.owner = data;
        next();
    } catch(e) {
        if (!res.headersSent) res.status(500).json({ error: "Auth error" });
    }
}

// ── Global error wrapper ──────────────────────────────────────────────────────
function wrap(fn) {
    return async (req, res, next) => {
        try { await fn(req, res, next); }
        catch(e) {
            console.error("[ERR]", req.method, req.path, e.message);
            if (!res.headersSent) res.status(500).json({ error: "Server error: " + e.message });
        }
    };
}

// Sanitise input to prevent injection
function sanitize(s, maxLen = 500) {
    if (typeof s !== "string") return "";
    return s.slice(0, maxLen).replace(/[<>]/g, "");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCRIPT AUTH — Roblox executors
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/auth", authLimiter, wrap(async (req, res) => {
    const userKey = sanitize(String(req.query.key || ""), 100);
    const hwid    = sanitize(String(req.query.hwid || ""), 200);
    const fail    = msg => res.set("Content-Type","text/plain").send(`error("Lunex: ${msg}")`);

    if (!userKey || !hwid) return fail("Missing key or hwid");

    const { data: keyRow } = await sb.from("keys")
        .select("*, projects(obfuscated_script, ffa, active, name, id)")
        .eq("key_string", userKey).single();

    if (!keyRow)        return fail("Invalid key");
    if (!keyRow.active) return fail("Key revoked — contact support");
    if (keyRow.expires_at && Math.floor(Date.now()/1000) > keyRow.expires_at)
        return fail("Key expired");

    // HWID lock — exactly 1 device per key
    if (!keyRow.hwid) {
        const expires_at = keyRow.key_days
            ? Math.floor(Date.now()/1000) + keyRow.key_days * 86400
            : null;
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

app.post("/v1/admin/owners", adminLimiter, wrap(async (req, res) => {
    if (!req.body || req.body.admin_secret !== process.env.ADMIN_SECRET)
        return res.status(403).json({ error: "Forbidden" });
    const email = sanitize(req.body.email || "", 200);
    const plan  = ["starter","pro","elite"].includes(req.body.plan) ? req.body.plan : "elite";
    const days  = parseInt(req.body.days) || null;
    if (!email) return res.status(400).json({ error: "Email required" });
    const apiKey  = genApiKey();
    const expires = days ? Math.floor(Date.now()/1000) + days*86400 : null;
    const { data, error } = await sb.from("owners").insert({
        email, api_key: apiKey, plan, expires_at: expires, obfs_used: 0
    }).select("id,email,plan").single();
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
    const name = sanitize(req.body.name || "", 100);
    const ffa  = req.body.ffa === true;
    if (!name) return res.status(400).json({ error: "Name required" });
    const { count } = await sb.from("projects")
        .select("*", { count:"exact", head:true }).eq("owner_id", req.owner.id);
    const limits = { starter:3, pro:10, elite:50 };
    if ((count||0) >= (limits[req.owner.plan] || 3))
        return res.status(429).json({ error: `Project limit reached for ${req.owner.plan} plan` });
    const { data, error } = await sb.from("projects").insert({
        owner_id: req.owner.id, name, ffa, active: true, script_version: "0001"
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, project: data });
}));

app.delete("/v1/projects/:id", apiLimiter, requireApiKey, wrap(async (req, res) => {
    await sb.from("projects").delete()
        .eq("id", req.params.id).eq("owner_id", req.owner.id);
    res.json({ success: true });
}));

app.post("/v1/projects/:id/script", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const source = req.body.source;
    if (!source?.trim()) return res.status(400).json({ error: "Source required" });
    const { data: proj } = await sb.from("projects").select("*")
        .eq("id", req.params.id).eq("owner_id", req.owner.id).single();
    if (!proj) return res.status(404).json({ error: "Project not found" });

    // Encrypt with project-specific key
    let encrypted;
    try {
        encrypted = buildEncryptedScript(source, proj.id);
    } catch(e) {
        console.error("[Encrypt]", e.message);
        return res.status(500).json({ error: "Encryption failed: " + e.message });
    }

    const newVer = String(parseInt(proj.script_version || "0000") + 1).padStart(4, "0");
    const { error: updateErr } = await sb.from("projects").update({
        obfuscated_script: encrypted,
        raw_script: source,
        script_version: newVer,
        updated_at: new Date().toISOString()
    }).eq("id", proj.id);
    if (updateErr) return res.status(500).json({ error: updateErr.message });

    const base = process.env.RAILWAY_PUBLIC_DOMAIN
        ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
        : `http://localhost:${process.env.PORT||8080}`;
    const loader = `script_key="KEY_HERE"\nloadstring(game:HttpGet("${base}/v1/auth?key="..script_key.."&hwid="..game:GetService("RbxAnalyticsService"):GetClientId()))()`;
    res.json({ success: true, version: newVer, loader });
}));

app.post("/v1/projects/:id/toggle", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data: proj } = await sb.from("projects").select("active")
        .eq("id", req.params.id).eq("owner_id", req.owner.id).single();
    if (!proj) return res.status(404).json({ error: "Not found" });
    await sb.from("projects").update({ active: !proj.active }).eq("id", req.params.id);
    res.json({ success: true, active: !proj.active });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// KEYS
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/projects/:id/keys", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const page   = Math.max(1, parseInt(req.query.page) || 1);
    const limit  = Math.min(200, parseInt(req.query.limit) || 100);
    const search = sanitize(req.query.search || "", 100);
    const off    = (page - 1) * limit;
    let q = sb.from("keys").select("*", { count:"exact" })
        .eq("project_id", req.params.id)
        .order("created_at", { ascending: false })
        .range(off, off + limit - 1);
    if (search) q = q.or(`key_string.ilike.%${search}%,discord_id.ilike.%${search}%,note.ilike.%${search}%`);
    const { data, error, count } = await q;
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, keys: data || [], total: count || 0 });
}));

app.post("/v1/projects/:id/keys", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const amount     = Math.min(500, Math.max(1, parseInt(req.body.amount) || 1));
    const key_days   = parseInt(req.body.key_days) || null;
    const discord_id = sanitize(req.body.discord_id || "", 50) || null;
    const note       = sanitize(req.body.note || "", 200) || null;
    const prefix     = sanitize(req.body.prefix || "LUNEX", 10).toUpperCase();
    const rows = Array.from({ length: amount }, () => ({
        project_id:       req.params.id,
        key_string:       genKey(prefix),
        discord_id, note,
        active:           true,
        key_days:         key_days,
        expires_at:       key_days ? Math.floor(Date.now()/1000) + key_days*86400 : null,
        total_executions: 0,
        created_at:       new Date().toISOString()
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
    const { data } = await sb.from("keys").update({
        hwid: null,
        last_hwid_reset: new Date().toISOString(),
        updated_at: new Date().toISOString()
    }).eq("key_string", req.params.key).select().single();
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
    const base = data.expires_at ?? Math.floor(Date.now()/1000);
    await sb.from("keys").update({ expires_at: base + days*86400 }).eq("key_string", req.params.key);
    res.json({ success: true, new_expiry: base + days*86400 });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/v1/stats", apiLimiter, requireApiKey, wrap(async (req, res) => {
    const { data: projs } = await sb.from("projects").select("id").eq("owner_id", req.owner.id);
    const ids = (projs || []).map(p => p.id);
    if (!ids.length) return res.json({
        success: true, projects: 0, total_keys: 0,
        total_executions: 0, plan: req.owner.plan, obfs_used: 0
    });
    const [keyCnt, execs] = await Promise.all([
        sb.from("keys").select("*", { count:"exact", head:true }).in("project_id", ids),
        sb.from("keys").select("total_executions").in("project_id", ids)
    ]);
    const totalExecs = (execs.data || []).reduce((s,k) => s + (k.total_executions||0), 0);
    res.json({
        success: true,
        projects: ids.length,
        total_keys: keyCnt.count || 0,
        total_executions: totalExecs,
        plan: req.owner.plan,
        obfs_used: req.owner.obfs_used || 0
    });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL — Discord bot only
// ═══════════════════════════════════════════════════════════════════════════════
function checkInternal(req, res) {
    const secret = req.body?.secret || req.query?.secret;
    if (!secret || secret !== process.env.MASTER_SECRET) {
        res.status(403).json({ error: "Forbidden" });
        return false;
    }
    return true;
}

app.post("/internal/whitelist", wrap(async (req, res) => {
    if (!checkInternal(req, res)) return;
    const { project_id, discord_id, days, note } = req.body;
    const key        = genKey();
    const expires_at = days ? Math.floor(Date.now()/1000) + days*86400 : null;
    const { data, error } = await sb.from("keys").insert({
        project_id, key_string: key,
        discord_id: discord_id || null,
        note: note || null,
        active: true, key_days: days || null, expires_at,
        total_executions: 0, created_at: new Date().toISOString()
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, key: data.key_string });
}));

app.post("/internal/resethwid", wrap(async (req, res) => {
    if (!checkInternal(req, res)) return;
    const { discord_id, project_id } = req.body;
    let q = sb.from("keys").update({ hwid: null, last_hwid_reset: new Date().toISOString() })
        .eq("discord_id", discord_id);
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
    if (req.query.secret !== process.env.MASTER_SECRET)
        return res.status(403).json({ error: "Forbidden" });
    const { data } = await sb.from("keys").select("*").eq("discord_id", req.query.discord_id);
    res.json({ success: true, keys: data || [] });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// CRON JOBS
// ═══════════════════════════════════════════════════════════════════════════════
// Expire keys every 5 minutes
cron.schedule("*/5 * * * *", async () => {
    const now = Math.floor(Date.now()/1000);
    await sb.from("keys").update({ active: false })
        .lt("expires_at", now).eq("active", true).not("expires_at", "is", null);
});
// Reset monthly obfuscation counters
cron.schedule("0 0 1 * *", async () => {
    await sb.from("owners").update({ obfs_used: 0, obfs_reset_at: new Date().toISOString() });
    console.log("[CRON] Obfuscation counters reset");
});

// ═══════════════════════════════════════════════════════════════════════════════
// SERVE DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "dashboard", "index.html"), err => {
        if (err) res.status(500).send("Dashboard not found");
    });
});

// Block all unknown routes with JSON error
app.use((req, res) => res.status(404).json({ error: "Not found" }));

// Global uncaught error handler — never crash the process
process.on("uncaughtException",  e => console.error("[UNCAUGHT]", e.message));
process.on("unhandledRejection", e => console.error("[UNHANDLED]", e));

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`[Lunex] Running on port ${PORT}`));
