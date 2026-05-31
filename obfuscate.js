// Prometheus obfuscator running via wasmoon (Lua WASM)
// Mirrors exactly how the Prometheus web UI works

const SOURCES = require("./prometheusLua.js");

let luaFactoryPromise = null;

async function getLuaFactory() {
    if (!luaFactoryPromise) {
        luaFactoryPromise = (async () => {
            const mod = require("wasmoon");
            return mod.LuaFactory;
        })();
    }
    return luaFactoryPromise;
}

// Convert string to Lua long string literal
function toLuaLongString(s) {
    // Find the right level of = so it doesn't conflict with content
    let level = 0;
    while (s.includes(`]${"=".repeat(level)}]`)) level++;
    const eq = "=".repeat(level);
    return `[${ eq }[${ s }]${ eq }]`;
}

function buildBootstrap() {
    return Object.entries(SOURCES).map(([name, source]) => {
        const chunkName = `@/src/${name.split(".").join("/")}.lua`;
        return `
package.preload[${toLuaLongString(name)}] = function(...)
  local chunk, err = load(${toLuaLongString(source)}, ${toLuaLongString(chunkName)}, "t")
  if not chunk then error(err) end
  return chunk(...)
end`;
    }).join("\n");
}

function buildRunLua(source, preset, seed) {
    return `
_G.arg = _G.arg or {}
${buildBootstrap()}

local logs = {}
local unpackFn = table.unpack or unpack

if not math.log10 then
  math.log10 = function(v) return math.log(v, 10) end
end

local Prometheus = require("prometheus")
Prometheus.Logger.logLevel = Prometheus.Logger.LogLevel.Info
Prometheus.colors.enabled = false
Prometheus.Logger.debugCallback = function(...) end
Prometheus.Logger.logCallback   = function(...) end
Prometheus.Logger.warnCallback  = function(...) end
Prometheus.Logger.errorCallback = function(...)
  local parts = {}
  for i=1,select("#",...) do parts[#parts+1]=tostring(select(i,...)) end
  error(table.concat(parts," "))
end

local ok, outputOrError = xpcall(function()
  local config = {}
  for k,v in pairs(Prometheus.Presets[${toLuaLongString(preset)}]) do
    config[k] = v
  end
  config.LuaVersion = "Lua51"
  config.PrettyPrint = false
  config.Seed = ${Math.max(1, seed)}
  return Prometheus.Pipeline:fromConfig(config):apply(${toLuaLongString(source)}, "script.lua")
end, debug.traceback)

return { ok=ok, output=ok and outputOrError or "", error=ok and "" or outputOrError }
`;
}

async function obfuscate(source, level = "full") {
    if (!source || !source.trim()) throw new Error("Source is empty");

    // Map our levels to Prometheus presets
    const preset = level === "light" ? "Medium" : "Strong";
    const seed   = Math.floor(Math.random() * 999999) + 1;

    const LuaFactory = await getLuaFactory();
    let lua = null;
    try {
        lua = await new LuaFactory().createEngine({ openStandardLibs: true });
        const runLua = buildRunLua(source, preset, seed);
        const result = await lua.doString(runLua);

        if (!result || result.ok === false) {
            throw new Error(result ? String(result.error || "Prometheus failed") : "No result returned");
        }

        return String(result.output || "");
    } catch(e) {
        throw new Error("Prometheus obfuscation failed: " + e.message);
    } finally {
        if (lua) try { lua.global.close(); } catch {}
    }
}

module.exports = { obfuscate };
