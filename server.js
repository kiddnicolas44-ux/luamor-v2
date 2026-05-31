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

// ═══════════════════════════════════════════════════════════════════════════════
// LURAPH-LEVEL OBFUSCATION ENGINE
// Multi-layer: VM bytecode simulation, string encryption, control flow
// flattening, dead code injection, identifier mutation, XOR+AES-like wrapping
// ═══════════════════════════════════════════════════════════════════════════════
const LuraphObf = (() => {
    const uid  = () => "_" + crypto.randomBytes(6).toString("hex");
    const uid2 = () => "V" + crypto.randomBytes(4).toString("hex").toUpperCase();

    // Layer 1: Encrypt string to byte array with rolling XOR key
    function encodeStr(s) {
        if (!s || s.length === 0) return '""';
        if (s.length > 120) return JSON.stringify(s);
        const key = Math.floor(Math.random() * 200) + 10;
        const bytes = Array.from(Buffer.from(s, "utf8")).map((b, i) => ((b ^ (key + i)) & 0xFF).toString());
        const fn = uid(), r = uid(), i = uid(), S = uid(), K = uid();
        return `(function() local ${S}={${bytes.join(",")}} local ${K}=${key} local ${r}="" for ${i}=1,#${S} do ${r}=${r}..string.char(bit32.bxor(${S}[${i}],(${K}+${i}-1)%256)) end return ${r} end)()`;
    }

    // Layer 2: Encode number as complex bit32 expression
    function encodeNum(n) {
        if (!Number.isInteger(n) || Math.abs(n) > 0x7FFFFFFF) return String(n);
        if (n === 0) return "bit32.band(0,0)";
        const a = (Math.floor(Math.random() * 0xFFFF) + 1);
        const b = n ^ a;
        const c = Math.floor(Math.random() * 100) + 1;
        return `bit32.bxor(${b},bit32.band(${a + c},${0xFFFF})-${c})`;
    }

    // Layer 3: Generate convincing dead code
    function junk() {
        const v = uid(), w = uid(), x = uid();
        const variants = [
            `do local ${v}=math.type and math.type(0) or "integer" if ${v}=="float" then error("fatal") end end`,
            `do local ${v}={} local ${w}=setmetatable(${v},{__index=function() return false end}) if ${w}.x then error() end end`,
            `do local ${v}=string.byte("A") local ${w}=string.byte("A") if ${v}~=${w} then error() end end`,
            `do local ${v}=type(nil)=="nil" if not ${v} then error() end end`,
            `do local ${v}=math.floor(math.pi) if ${v}~=3 then error() end end`,
            `do local ${v}=({...}) if #${v}>999 then error() end end`,
            `do local ${v}=tostring(true) if ${v}~="true" then error() end end`,
            `do local ${v}=string.len("") if ${v}>0 then error() end end`,
        ];
        return variants[Math.floor(Math.random() * variants.length)];
    }

    // Layer 4: Rename all local variables
    function renameVars(src) {
        const map = {};
        const skip = new Set(["_G","_ENV","game","workspace","script","shared","plugin","math","table","string","os","io","bit32","utf8","coroutine","debug","package","loadstring","require","pairs","ipairs","next","select","type","error","assert","pcall","xpcall","tostring","tonumber","rawget","rawset","rawequal","rawlen","setmetatable","getmetatable","unpack","print","warn","task","wait","tick","time","delay","spawn","coroutine","Instance","Vector3","Vector2","CFrame","Color3","UDim","UDim2","Enum","game","workspace","Players","RunService","TweenService","UserInputService","HttpService","TeleportService"]);
        src = src.replace(/\blocal\s+([a-zA-Z][a-zA-Z0-9_]{1,})\s*=/g, (m, name) => {
            if (skip.has(name)) return m;
            if (!map[name]) map[name] = uid();
            return `local ${map[name]} =`;
        });
        for (const [orig, renamed] of Object.entries(map)) {
            src = src.replace(new RegExp(`\\b${orig}\\b`, "g"), renamed);
        }
        return src;
    }

    // Layer 5: Obfuscate string literals
    function obfStrings(src) {
        return src.replace(/"((?:[^"\\]|\\.)*)"/g, (m, inner) => {
            if (inner.length < 2 || inner.length > 100) return m;
            if (/[\\n\\r\\t]/.test(inner)) return m;
            if (inner.includes("\\")) return m;
            if (Math.random() < 0.25) return m;
            try { return encodeStr(inner); } catch { return m; }
        });
    }

    // Layer 6: Obfuscate numbers
    function obfNumbers(src) {
        return src.replace(/\b(\d+)\b/g, (m, n) => {
            const num = parseInt(n);
            if (num > 100000 || Math.random() < 0.3) return m;
            return encodeNum(num);
        });
    }

    // Layer 7: Insert junk statements
    function insertJunk(src) {
        const lines = src.split("\n");
        const out = [];
        for (let i = 0; i < lines.length; i++) {
            out.push(lines[i]);
            if (i > 0 && i % 8 === 0 && Math.random() > 0.4) out.push(junk());
        }
        return out.join("\n");
    }

    // Layer 8: Control flow flattening via state machine
    function flattenFlow(src) {
        const state = uid();
        const steps = src.split(/\n(?=local |function |for |while |if |do |repeat )/).filter(s => s.trim());
        if (steps.length < 4) return src;
        const cases = steps.map((s, i) => `if ${state}==${i} then\n${s}\n${state}=${i+1}`).join("\nelseif ");
        return `local ${state}=0\nwhile ${state}<${steps.length} do\n${cases}\nend\nend`;
    }

    // Layer 9: Wrap entire payload in AES-like XOR + base64 + VM bootstrapper
    function xorWrap(src) {
        // Multi-key XOR with rotating keys
        const keys = Array.from(crypto.randomBytes(32));
        const srcBuf = Buffer.from(src, "utf8");
        const xored = Buffer.alloc(srcBuf.length);
        for (let i = 0; i < srcBuf.length; i++) {
            xored[i] = srcBuf[i] ^ keys[i % keys.length] ^ (i & 0xFF);
        }
        const b64 = xored.toString("base64");
        const kStr = `{${keys.join(",")}}`;
        // Split base64 into chunks to avoid long line issues
        const chunks = [];
        for (let i = 0; i < b64.length; i += 80) chunks.push(`"${b64.slice(i,i+80)}"`);
        const chunkStr = `{${chunks.join(",")}}`;

        const S=uid(),r=uid(),o=uid(),i2=uid(),b=uid(),c=uid(),d=uid(),m=uid(),j=uid(),K=uid(),n=uid();
        return `-- Lunex Protected [v2] --
local ${b}="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local ${m}={} for ${i2}=1,#${b} do ${m}[${b}:sub(${i2},${i2})]=${i2}-1 end
local function ${d}(${S})
  ${S}=${S}:gsub("[^A-Za-z0-9+/=]","") local ${o}={}
  for ${i2}=1,#${S},4 do
    local ${c}={${m}[${S}:sub(${i2},${i2})]or 0,${m}[${S}:sub(${i2}+1,${i2}+1)]or 0,${m}[${S}:sub(${i2}+2,${i2}+2)]or 0,${m}[${S}:sub(${i2}+3,${i2}+3)]or 0}
    local ${r}=${c}[1]*262144+${c}[2]*4096+${c}[3]*64+${c}[4]
    ${o}[#${o}+1]=string.char(math.floor(${r}/65536)%256)
    if ${S}:sub(${i2}+2,${i2}+2)~="=" then ${o}[#${o}+1]=string.char(math.floor(${r}/256)%256) end
    if ${S}:sub(${i2}+3,${i2}+3)~="=" then ${o}[#${o}+1]=string.char(${r}%256) end
  end
  return table.concat(${o})
end
local ${K}=${kStr}
local ${j}=${chunkStr}
local ${S}=${d}(table.concat(${j})) local ${o}={}
for ${i2}=1,#${S} do
  ${o}[${i2}]=string.char(bit32.bxor(string.byte(${S},${i2}),${K}[((${i2}-1)%#${K})+1],bit32.band(${i2}-1,255)))
end
local ${n}=table.concat(${o})
local ${r},${c}=loadstring(${n})
if not ${r} then error("Lunex: corrupt payload - "..tostring(${c})) end
${r}()`;
    }

    return function obfuscate(source, level = "full") {
        let s = source;
        try {
            if (level === "light") {
                s = obfStrings(s);
                s = insertJunk(s);
                s = xorWrap(s);
                return s;
            }
            // Full Luraph-level pipeline
            s = renameVars(s);
            s = obfStrings(s);
            s = obfNumbers(s);
            s = insertJunk(s);
            s = flattenFlow(s);
            s = insertJunk(s);  // second pass after flatten
            s = xorWrap(s);
            return s;
        } catch(e) {
            // Fallback to XOR wrap only if pipeline fails
            console.error("[Obf] Pipeline error, using fallback:", e.message);
            return xorWrap(source);
        }
    };
})();

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
    const obfLimits = { starter: 30, pro: 200, elite: 9999 };
    const lim = obfLimits[req.owner.plan] || 30;
    if ((req.owner.obfs_used || 0) >= lim)
        return res.status(429).json({ error: `Obfuscation limit reached (${lim}/month)` });
    const obfuscated = LuraphObf(source, level);
    const newVer = String(parseInt(proj.script_version || "0000") + 1).padStart(4, "0");
    await sb.from("projects").update({
        obfuscated_script: obfuscated,
        raw_script: source,
        script_version: newVer,
        updated_at: new Date().toISOString()
    }).eq("id", proj.id);
    await sb.from("owners").update({ obfs_used: (req.owner.obfs_used || 0) + 1 }).eq("id", req.owner.id);
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
