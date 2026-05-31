// Prometheus obfuscator using wasmoon (Lua WASM in Node.js)
// Mirrors exactly how the Nexa Python app works, with fix_lua preprocessing

const SOURCES = require("./prometheusLua.js");

// ── Replicate Python's fix_lua() ──────────────────────────────────────────────
// Converts LuaU-only syntax to standard Lua 5.1 so Prometheus can parse it
function fixLua(code) {
    // Fix compound assignments: x += y -> x = x + y
    code = code.replace(
        /([a-zA-Z_][a-zA-Z0-9_.\[\]"']*)\s*([+\-*\/%]|\.\.)\s*=\s*([^\n]+)/g,
        (m, varName, op, val) => `${varName} = ${varName} ${op} ${val.trim()}`
    );
    // Remove continue statements (not in Lua 5.1)
    code = code.replace(/if\s+.+?\s+then\s+continue\s+end/g, "");
    code = code.replace(/if\s+[^\n]+then\s*\n\s*continue\s*\n\s*end/gm, "");
    code = code.replace(/^\s*continue\s*$/gm, "");
    // Fix unicode chars
    code = code.replace(/\xd7/g, "x").replace(/\xb7/g, ".");
    // Remove type annotations (LuaU): local x: Type = ...
    code = code.replace(/:\s*[A-Z][a-zA-Z0-9_<>, |?*\[\]]*\s*=/g, " =");
    code = code.replace(/:\s*[A-Z][a-zA-Z0-9_<>, |?*\[\]]*(\s*[,)\n])/g, "$1");
    return code;
}

// ── Convert string to Lua long string ────────────────────────────────────────
function toLuaLong(s) {
    let level = 0;
    while (s.includes(`]${"=".repeat(level)}]`)) level++;
    const eq = "=".repeat(level);
    return `[${eq}[${s}]${eq}]`;
}

// ── Build Lua bootstrap that loads all Prometheus modules ─────────────────────
function buildBootstrap() {
    return Object.entries(SOURCES).map(([name, src]) => {
        return `package.preload[${toLuaLong(name)}]=function(...)\nlocal f,e=load(${toLuaLong(src)},"@${name}.lua","t")\nif not f then error(e) end\nreturn f(...)\nend`;
    }).join("\n");
}

// ── Main obfuscation Lua script ───────────────────────────────────────────────
function buildRunLua(source, preset, seed) {
    return `
_G.arg=_G.arg or {}
${buildBootstrap()}
if not math.log10 then math.log10=function(v) return math.log(v,10) end end
local Prometheus=require("prometheus")
Prometheus.Logger.logLevel=Prometheus.Logger.LogLevel.Info
Prometheus.colors.enabled=false
Prometheus.Logger.debugCallback=function() end
Prometheus.Logger.logCallback=function() end
Prometheus.Logger.warnCallback=function() end
Prometheus.Logger.errorCallback=function(...)
  local t={} for i=1,select("#",...)do t[#t+1]=tostring(select(i,...))end
  error(table.concat(t," "))
end
local ok,result=xpcall(function()
  local cfg={}
  for k,v in pairs(Prometheus.Presets[${toLuaLong(preset)}])do cfg[k]=v end
  cfg.LuaVersion="Lua51"
  cfg.PrettyPrint=false
  cfg.Seed=${Math.max(1, seed)}
  return Prometheus.Pipeline:fromConfig(cfg):apply(${toLuaLong(source)},"script.lua")
end,debug.traceback)
return {ok=ok,output=ok and result or "",error=ok and "" or result}
`;
}

// ── Lazy-load LuaFactory ──────────────────────────────────────────────────────
let _luaFactory = null;
async function getLuaFactory() {
    if (!_luaFactory) {
        const mod = require("wasmoon");
        _luaFactory = mod.LuaFactory;
    }
    return _luaFactory;
}

// ── Main export ───────────────────────────────────────────────────────────────
async function obfuscate(source, level = "full") {
    if (!source || !source.trim()) throw new Error("Source is empty");

    // Pre-process LuaU syntax (same as Python's fix_lua)
    const fixed = fixLua(source);

    // Map level to Prometheus preset
    const preset = level === "light" ? "Medium" : "Strong";
    const seed   = Math.floor(Math.random() * 999998) + 1;

    const LuaFactory = await getLuaFactory();
    let lua = null;
    try {
        lua = await new LuaFactory().createEngine({ openStandardLibs: true });
        const runLua = buildRunLua(fixed, preset, seed);
        const result = await lua.doString(runLua);

        if (!result || result.ok === false) {
            const errMsg = result ? String(result.error || "Prometheus failed") : "No result";
            throw new Error(errMsg);
        }

        const output = String(result.output || "");
        if (!output.trim()) throw new Error("Prometheus produced empty output");
        return output;

    } catch(e) {
        throw new Error("Obfuscation failed: " + e.message);
    } finally {
        if (lua) try { lua.global.close(); } catch {}
    }
}

module.exports = { obfuscate };
