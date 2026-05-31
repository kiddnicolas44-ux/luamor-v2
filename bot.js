require("dotenv").config();
const {
    Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes,
    EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle,
    ModalBuilder, TextInputBuilder, TextInputStyle,
    PermissionFlagsBits, ActivityType
} = require("discord.js");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const sb     = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const SECRET = process.env.MASTER_SECRET;
const BASE   = process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${process.env.PORT || 8080}`;

// ── Colors ────────────────────────────────────────────────────────────────────
const C = { main:0x4f8ef7, ok:0x23d18b, err:0xf75050, warn:0xf5a623, dark:0x0d1117 };

// ── Helpers ───────────────────────────────────────────────────────────────────
function genKey(prefix="LUNEX") {
    const seg = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${seg()}-${seg()}-${seg()}`;
}

function formatExpiry(k) {
    if (!k.expires_at) return "♾️ Lifetime";
    const sec = k.expires_at - Math.floor(Date.now() / 1000);
    if (sec <= 0) return "⛔ Expired";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    return d > 0 ? `⏳ ${d}d ${h}h` : `⏳ ${h}h ${Math.floor((sec%3600)/60)}m`;
}

async function getCfg(guildId) {
    const { data } = await sb.from("bot_configs").select("*").eq("guild_id", guildId).single();
    return data;
}
async function setCfg(guildId, updates) {
    const { data } = await sb.from("bot_configs")
        .upsert({ guild_id: guildId, ...updates, updated_at: new Date().toISOString() }, { onConflict: "guild_id" })
        .select().single();
    return data;
}

function isManager(member, cfg) {
    if (!member) return false;
    if (member.permissions.has(PermissionFlagsBits.Administrator)) return true;
    if (cfg?.manager_role_id && member.roles.cache.has(cfg.manager_role_id)) return true;
    return false;
}

// ── PANEL BUILDER ─────────────────────────────────────────────────────────────
function buildPanel(cfg) {
    const name = cfg?.project_name || "Script";
    const embed = new EmbedBuilder()
        .setColor(C.main)
        .setTitle(`${name} Control Panel`)
        .setDescription(
            `This control panel is for the project: **${name}**\n` +
            `If you're a buyer, click on the buttons below to redeem your key, get the script or get your role.`
        )
        .setFooter({ text: `Lunex • ${new Date().toLocaleString("en-US",{month:"short",day:"numeric",year:"numeric",hour:"2-digit",minute:"2-digit"})}` })
        .setTimestamp();

    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId("panel_redeem").setLabel("Redeem Key").setEmoji("🔑").setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId("panel_script").setLabel("Get Script").setEmoji("📋").setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId("panel_role").setLabel("Get Role").setEmoji("🎭").setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId("panel_hwid").setLabel("Reset HWID").setEmoji("⚙️").setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId("panel_stats").setLabel("Get Stats").setEmoji("📊").setStyle(ButtonStyle.Secondary)
    );
    return { embeds:[embed], components:[row] };
}

// ── COMMANDS ──────────────────────────────────────────────────────────────────
const commands = [
    new SlashCommandBuilder()
        .setName("login").setDescription("Link this server to your Lunex account")
        .addStringOption(o=>o.setName("api_key").setDescription("Your API key from the dashboard").setRequired(true))
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

    new SlashCommandBuilder()
        .setName("setup").setDescription("Configure project & roles")
        .addStringOption(o=>o.setName("project_id").setDescription("Your project ID").setRequired(true))
        .addRoleOption(o=>o.setName("buyer_role").setDescription("Role given to buyers").setRequired(true))
        .addRoleOption(o=>o.setName("manager_role").setDescription("Role that can manage keys"))
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

    new SlashCommandBuilder()
        .setName("panel").setDescription("Post the control panel embed in this channel")
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageChannels),

    new SlashCommandBuilder()
        .setName("createkey").setDescription("Create a whitelist key for a user")
        .addUserOption(o=>o.setName("user").setDescription("Discord user to whitelist").setRequired(true))
        .addStringOption(o=>o.setName("duration").setDescription("Duration: 10m, 1h, 12h, 1d, 7d, 30d, lifetime").setRequired(true)
            .addChoices(
                {name:"10 Minutes",value:"10m"},
                {name:"1 Hour",value:"1h"},
                {name:"12 Hours",value:"12h"},
                {name:"1 Day",value:"1d"},
                {name:"3 Days",value:"3d"},
                {name:"7 Days",value:"7d"},
                {name:"30 Days",value:"30d"},
                {name:"Lifetime",value:"lifetime"}
            ))
        .addStringOption(o=>o.setName("note").setDescription("Optional note")),

    new SlashCommandBuilder()
        .setName("genkey").setDescription("Generate an unused key (for selling)")
        .addStringOption(o=>o.setName("duration").setDescription("Duration").setRequired(true)
            .addChoices(
                {name:"10 Minutes",value:"10m"},
                {name:"1 Hour",value:"1h"},
                {name:"12 Hours",value:"12h"},
                {name:"1 Day",value:"1d"},
                {name:"3 Days",value:"3d"},
                {name:"7 Days",value:"7d"},
                {name:"30 Days",value:"30d"},
                {name:"Lifetime",value:"lifetime"}
            ))
        .addIntegerOption(o=>o.setName("amount").setDescription("How many keys (default 1, max 50)"))
        .addStringOption(o=>o.setName("note").setDescription("Optional note")),

    new SlashCommandBuilder()
        .setName("revoke").setDescription("Revoke a user's key")
        .addUserOption(o=>o.setName("user").setDescription("User to revoke").setRequired(true)),

    new SlashCommandBuilder()
        .setName("resethwid").setDescription("Reset a user's HWID")
        .addUserOption(o=>o.setName("user").setDescription("User to reset").setRequired(true)),

    new SlashCommandBuilder()
        .setName("keyinfo").setDescription("View a user's key details")
        .addUserOption(o=>o.setName("user").setDescription("User to look up").setRequired(true)),

    new SlashCommandBuilder()
        .setName("stats").setDescription("View whitelist statistics")
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
];

// ── Parse duration string to seconds ─────────────────────────────────────────
function parseDuration(str) {
    if (str === "lifetime") return null;
    const map = { m:60, h:3600, d:86400 };
    const match = str.match(/^(\d+)([mhd])$/);
    if (!match) return null;
    return parseInt(match[1]) * (map[match[2]] || 0);
}

function durationLabel(str) {
    const labels = { "10m":"10 minutes","1h":"1 hour","12h":"12 hours","1d":"1 day","3d":"3 days","7d":"7 days","30d":"30 days","lifetime":"Lifetime" };
    return labels[str] || str;
}

// ── CLIENT ────────────────────────────────────────────────────────────────────
const client = new Client({
    intents:[
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.DirectMessages
    ]
});

// ── REPLY HELPERS ─────────────────────────────────────────────────────────────
async function reply(i, desc, color=C.main, ephemeral=true) {
    const method = i.deferred || i.replied ? "editReply" : "reply";
    return i[method]({ embeds:[new EmbedBuilder().setColor(color).setDescription(desc)], ephemeral });
}
async function replyEmbed(i, embed, ephemeral=true) {
    const method = i.deferred || i.replied ? "editReply" : "reply";
    return i[method]({ embeds:[embed], ephemeral });
}

// ── INTERACTION ───────────────────────────────────────────────────────────────
client.on("interactionCreate", async interaction => {
    try {
        if (interaction.isChatInputCommand()) return handleCommand(interaction);
        if (interaction.isButton())           return handleButton(interaction);
        if (interaction.isModalSubmit())      return handleModal(interaction);
    } catch(err) {
        console.error("[Bot] Error:", err);
    }
});

// ── COMMANDS ──────────────────────────────────────────────────────────────────
async function handleCommand(interaction) {
    const { commandName, guildId, member } = interaction;
    await interaction.deferReply({ ephemeral: true });

    const cfg = await getCfg(guildId);

    // /login
    if (commandName === "login") {
        const apiKey = interaction.options.getString("api_key");
        const r = await fetch(`${BASE}/v1/account`, {
            headers:{"Authorization":`Bearer ${apiKey}`}
        });
        const data = await r.json();
        if (!data.success) return reply(interaction, "❌ Invalid API key — check your dashboard", C.err);
        await setCfg(guildId, { api_key: apiKey, email: data.account.email, plan: data.account.plan });
        return replyEmbed(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Server Linked!")
            .addFields(
                {name:"Account",value:data.account.email,inline:true},
                {name:"Plan",value:`\`${data.account.plan}\``,inline:true}
            ).setDescription("Run `/setup` next to configure your project + roles."));
    }

    if (!cfg?.api_key) return reply(interaction, "❌ Run `/login <api_key>` first", C.err);

    // /setup
    if (commandName === "setup") {
        if (!member.permissions.has(PermissionFlagsBits.Administrator)) return reply(interaction,"❌ Admins only",C.err);
        const projectId   = interaction.options.getString("project_id");
        const buyerRole   = interaction.options.getRole("buyer_role");
        const managerRole = interaction.options.getRole("manager_role");
        const r = await fetch(`${BASE}/v1/projects`, { headers:{"Authorization":`Bearer ${cfg.api_key}`} });
        const data = await r.json();
        const proj = data.projects?.find(p=>p.id===projectId);
        if (!proj) return reply(interaction,"❌ Project not found — check the ID in your dashboard",C.err);
        await setCfg(guildId, {
            project_id:      projectId,
            project_name:    proj.name,
            buyer_role_id:   buyerRole.id,
            manager_role_id: managerRole?.id || null,
        });
        return replyEmbed(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Setup Complete")
            .addFields(
                {name:"Project",value:proj.name,inline:true},
                {name:"Buyer Role",value:`<@&${buyerRole.id}>`,inline:true},
                {name:"Manager Role",value:managerRole?`<@&${managerRole.id}>`:"Not set",inline:true}
            ).setDescription("Post a control panel with `/panel`"));
    }

    // /panel
    if (commandName === "panel") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        await interaction.channel.send(buildPanel(cfg));
        return reply(interaction,"✅ Control panel posted!",C.ok);
    }

    // /createkey
    if (commandName === "createkey") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        const target   = interaction.options.getUser("user");
        const duration = interaction.options.getString("duration");
        const note     = interaction.options.getString("note") || null;
        const secs     = parseDuration(duration);
        const expires_at = secs ? Math.floor(Date.now()/1000)+secs : null;
        const key = genKey();
        const { data, error } = await sb.from("keys").insert({
            project_id:       cfg.project_id,
            key_string:       key,
            discord_id:       target.id,
            note,
            active:           true,
            key_days:         secs ? Math.ceil(secs/86400) : null,
            expires_at,
            total_executions: 0,
            created_at:       new Date().toISOString()
        }).select().single();
        if (error) return reply(interaction,`❌ ${error.message}`,C.err);

        // Give buyer role
        try {
            const gm = await interaction.guild.members.fetch(target.id);
            if (cfg.buyer_role_id) await gm.roles.add(cfg.buyer_role_id);
        } catch {}

        // DM user
        try {
            await target.send({ embeds:[new EmbedBuilder()
                .setColor(C.ok).setTitle("🔑 You've Been Whitelisted!")
                .setDescription(`Your key for **${cfg.project_name||"the script"}**:`)
                .addFields(
                    {name:"Key",value:`\`\`\`${key}\`\`\``,inline:false},
                    {name:"Duration",value:durationLabel(duration),inline:true},
                    {name:"Usage",value:`Put \`script_key="${key}";\` above the loader`,inline:false}
                ).setFooter({text:"Do not share your key — HWID locks on first run"})]
            });
        } catch {}

        return replyEmbed(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Key Created")
            .setDescription(`<@${target.id}> has been whitelisted and DM'd their key.`)
            .addFields(
                {name:"Key",value:`\`${key}\``,inline:false},
                {name:"Duration",value:durationLabel(duration),inline:true},
                {name:"Note",value:note||"None",inline:true}
            ));
    }

    // /genkey
    if (commandName === "genkey") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        const duration = interaction.options.getString("duration");
        const amount   = Math.min(interaction.options.getInteger("amount")||1, 50);
        const note     = interaction.options.getString("note")||null;
        const secs     = parseDuration(duration);
        const expires_at = secs ? Math.floor(Date.now()/1000)+secs : null;

        const rows = Array.from({length:amount}, () => ({
            project_id: cfg.project_id,
            key_string: genKey(),
            discord_id: null, note,
            active: true,
            key_days: secs ? Math.ceil(secs/86400) : null,
            expires_at,
            total_executions: 0,
            created_at: new Date().toISOString()
        }));
        const { data, error } = await sb.from("keys").insert(rows).select("key_string");
        if (error) return reply(interaction,`❌ ${error.message}`,C.err);

        const keyList = data.map(k=>k.key_string).join("\n");
        return interaction.editReply({
            embeds:[new EmbedBuilder().setColor(C.ok).setTitle("🗝️ Keys Generated")
                .setDescription(`Generated **${data.length}** key${data.length!==1?"s":""} — ${durationLabel(duration)}`)],
            files:[{attachment:Buffer.from(keyList),name:`keys_${Date.now()}.txt`}],
            ephemeral:true
        });
    }

    // /revoke
    if (commandName === "revoke") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        const target = interaction.options.getUser("user");
        await sb.from("keys").update({active:false}).eq("discord_id",target.id).eq("project_id",cfg.project_id);
        try {
            const gm = await interaction.guild.members.fetch(target.id);
            if (cfg.buyer_role_id) await gm.roles.remove(cfg.buyer_role_id).catch(()=>{});
        } catch {}
        try { await target.send({embeds:[new EmbedBuilder().setColor(C.err)
            .setTitle("🚫 Access Revoked").setDescription("Your whitelist access has been revoked.")]}); } catch {}
        return reply(interaction,`✅ Revoked access for <@${target.id}>`,C.ok);
    }

    // /resethwid
    if (commandName === "resethwid") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        const target = interaction.options.getUser("user");
        const {data} = await sb.from("keys").update({hwid:null,last_hwid_reset:new Date().toISOString()})
            .eq("discord_id",target.id).eq("project_id",cfg.project_id).select("key_string");
        if (!data?.length) return reply(interaction,"❌ No key found for this user",C.err);
        try { await target.send({embeds:[new EmbedBuilder().setColor(C.main)
            .setTitle("🔓 HWID Reset").setDescription("Your HWID has been reset. New HWID locks on next script run.")]}); } catch {}
        return reply(interaction,`✅ HWID reset for <@${target.id}>`,C.ok);
    }

    // /keyinfo
    if (commandName === "keyinfo") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        const target = interaction.options.getUser("user");
        const {data} = await sb.from("keys").select("*").eq("discord_id",target.id).eq("project_id",cfg.project_id).limit(1);
        if (!data?.length) return reply(interaction,"❌ No key found for this user",C.err);
        const k = data[0];
        return replyEmbed(interaction, new EmbedBuilder().setColor(k.active?C.main:C.err)
            .setTitle(`🔑 Key Info — ${target.username}`)
            .setThumbnail(target.displayAvatarURL())
            .addFields(
                {name:"Key",value:`\`${k.key_string}\``,inline:false},
                {name:"Status",value:k.active?"✅ Active":"❌ Revoked",inline:true},
                {name:"Expires",value:formatExpiry(k),inline:true},
                {name:"HWID",value:k.hwid?"🔒 Locked":"🔓 Unlocked",inline:true},
                {name:"Executions",value:String(k.total_executions||0),inline:true},
                {name:"Last Run",value:k.last_exec?`<t:${Math.floor(new Date(k.last_exec).getTime()/1000)}:R>`:"Never",inline:true},
                {name:"Note",value:k.note||"None",inline:true}
            ).setTimestamp());
    }

    // /stats
    if (commandName === "stats") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission",C.err);
        const {data:allKeys} = await sb.from("keys").select("active,expires_at,total_executions").eq("project_id",cfg.project_id);
        const now     = Math.floor(Date.now()/1000);
        const active  = (allKeys||[]).filter(k=>k.active&&(!k.expires_at||k.expires_at>now)).length;
        const expired = (allKeys||[]).filter(k=>k.expires_at&&k.expires_at<=now).length;
        const revoked = (allKeys||[]).filter(k=>!k.active).length;
        const totalR  = (allKeys||[]).reduce((s,k)=>s+(k.total_executions||0),0);
        return replyEmbed(interaction, new EmbedBuilder().setColor(C.main).setTitle("📊 Whitelist Stats")
            .addFields(
                {name:"🟢 Active",value:String(active),inline:true},
                {name:"⛔ Expired",value:String(expired),inline:true},
                {name:"🔴 Revoked",value:String(revoked),inline:true},
                {name:"⚡ Executions",value:String(totalR),inline:true}
            ).setTimestamp());
    }
}

// ── BUTTON HANDLER ────────────────────────────────────────────────────────────
async function handleButton(interaction) {
    const { customId, guildId, user } = interaction;
    const cfg = await getCfg(guildId);

    if (customId === "panel_redeem") {
        const modal = new ModalBuilder().setCustomId("modal_redeem").setTitle("Redeem a key");
        const input = new TextInputBuilder()
            .setCustomId("key_input").setLabel("Enter script key below:")
            .setPlaceholder("LUNEX-XXXXXX-XXXXXX-XXXXXX")
            .setStyle(TextInputStyle.Short).setRequired(true).setMinLength(10).setMaxLength(80);
        modal.addComponents(new ActionRowBuilder().addComponents(input));
        return interaction.showModal(modal);
    }

    if (customId === "panel_script") {
        await interaction.deferReply({ ephemeral:true });
        const {data} = await sb.from("keys").select("*").eq("discord_id",user.id).eq("project_id",cfg?.project_id).eq("active",true).limit(1);
        if (!data?.length) return reply(interaction,
            "❌ **Not whitelisted!**\n\nYou need to be whitelisted to get this script.\nIf you have a script key, click on the **Redeem Key** button to redeem it.",
            C.err);
        const k = data[0];
        const now = Math.floor(Date.now()/1000);
        if (k.expires_at && k.expires_at <= now) return reply(interaction,"❌ Your key has expired. Contact support.",C.err);
        const loader = `script_key="${k.key_string}";\nloadstring(game:HttpGet("${BASE}/v1/auth?key="..script_key.."&hwid="..game:GetService("RbxAnalyticsService"):GetClientId()))()`;
        try {
            await user.send({embeds:[new EmbedBuilder().setColor(C.main)
                .setTitle("📋 Your Script Loader")
                .setDescription("Copy the loader below and execute it in your Roblox executor.")
                .addFields(
                    {name:"Loader",value:`\`\`\`lua\n${loader}\n\`\`\``},
                    {name:"Expires",value:formatExpiry(k),inline:true},
                    {name:"Total Runs",value:String(k.total_executions||0),inline:true}
                ).setFooter({text:"Keep this private — your HWID locks on first run"})]
            });
            return reply(interaction,"✅ Script loader sent to your DMs!",C.ok);
        } catch {
            return reply(interaction,"❌ Couldn't DM you. Enable **Allow DMs from server members** in your privacy settings.",C.err);
        }
    }

    if (customId === "panel_role") {
        await interaction.deferReply({ ephemeral:true });
        if (!cfg?.buyer_role_id) return reply(interaction,"❌ No buyer role configured",C.err);
        const {data} = await sb.from("keys").select("*").eq("discord_id",user.id).eq("project_id",cfg.project_id).eq("active",true).limit(1);
        if (!data?.length) return reply(interaction,"❌ No active key found. Redeem a key first.",C.err);
        const k = data[0];
        const now = Math.floor(Date.now()/1000);
        if (k.expires_at && k.expires_at <= now) return reply(interaction,"❌ Your key has expired.",C.err);
        try {
            const gm = await interaction.guild.members.fetch(user.id);
            if (gm.roles.cache.has(cfg.buyer_role_id)) return reply(interaction,"✅ You already have the buyer role!",C.ok);
            await gm.roles.add(cfg.buyer_role_id);
            return reply(interaction,`✅ You've been given <@&${cfg.buyer_role_id}>!`,C.ok);
        } catch { return reply(interaction,"❌ Failed to assign role — make sure bot has **Manage Roles** above buyer role.",C.err); }
    }

    if (customId === "panel_hwid") {
        await interaction.deferReply({ ephemeral:true });
        const {data} = await sb.from("keys").select("*").eq("discord_id",user.id).eq("project_id",cfg?.project_id).limit(1);
        if (!data?.length) return reply(interaction,"❌ No key found for your account.",C.err);
        const k = data[0];
        await sb.from("keys").update({hwid:null,last_hwid_reset:new Date().toISOString()}).eq("key_string",k.key_string);
        return replyEmbed(interaction, new EmbedBuilder().setColor(C.ok).setTitle("🔓 HWID Reset")
            .setDescription("Your HWID has been cleared. Run the script again to lock your new device."));
    }

    if (customId === "panel_stats") {
        await interaction.deferReply({ ephemeral:true });
        const {data} = await sb.from("keys").select("*").eq("discord_id",user.id).eq("project_id",cfg?.project_id).limit(1);
        if (!data?.length) return reply(interaction,"❌ No key found. Redeem a key first.",C.err);
        const k = data[0];
        return replyEmbed(interaction, new EmbedBuilder().setColor(C.main).setTitle("📊 Your Stats")
            .addFields(
                {name:"Status",value:k.active?"✅ Active":"❌ Revoked",inline:true},
                {name:"Expires",value:formatExpiry(k),inline:true},
                {name:"HWID",value:k.hwid?"🔒 Locked":"🔓 Not locked",inline:true},
                {name:"Total Runs",value:String(k.total_executions||0),inline:true},
                {name:"Last Run",value:k.last_exec?`<t:${Math.floor(new Date(k.last_exec).getTime()/1000)}:R>`:"Never",inline:true},
                {name:"Key",value:`\`${k.key_string.slice(0,14)}...\``,inline:true}
            ).setFooter({text:cfg?.project_name||"Lunex"}).setTimestamp());
    }
}

// ── MODAL HANDLER ─────────────────────────────────────────────────────────────
async function handleModal(interaction) {
    const { customId, guildId, user } = interaction;
    const cfg = await getCfg(guildId);

    if (customId === "modal_redeem") {
        await interaction.deferReply({ ephemeral:true });
        const keyStr = interaction.fields.getTextInputValue("key_input").trim();
        const {data:keyRow} = await sb.from("keys").select("*").eq("key_string",keyStr).single();
        if (!keyRow) return reply(interaction,"❌ Invalid key — double-check and try again.",C.err);
        if (!keyRow.active) return reply(interaction,"❌ This key has been revoked.",C.err);
        if (keyRow.expires_at && keyRow.expires_at <= Math.floor(Date.now()/1000))
            return reply(interaction,"❌ This key has expired.",C.err);
        if (keyRow.discord_id && keyRow.discord_id !== user.id)
            return reply(interaction,"❌ This key is already claimed by another account.",C.err);
        if (!keyRow.discord_id)
            await sb.from("keys").update({discord_id:user.id}).eq("key_string",keyStr);
        try {
            if (cfg?.buyer_role_id) {
                const gm = await interaction.guild.members.fetch(user.id);
                await gm.roles.add(cfg.buyer_role_id);
            }
        } catch {}
        return replyEmbed(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Key Redeemed!")
            .setDescription("Your key has been linked to your account.\n\nUse **Get Script** to get your loader.")
            .addFields(
                {name:"Key",value:`\`${keyStr}\``,inline:false},
                {name:"Expires",value:formatExpiry(keyRow),inline:true}
            ).setFooter({text:"Do NOT share your key"}));
    }
}

// ── READY ─────────────────────────────────────────────────────────────────────
client.once("ready", async () => {
    console.log(`[Bot] Ready as ${client.user.tag}`);
    client.user.setActivity("Lunex Whitelist", { type: ActivityType.Watching });
    const rest = new REST({ version:"10" }).setToken(process.env.DISCORD_BOT_TOKEN);
    try {
        await rest.put(Routes.applicationCommands(process.env.DISCORD_CLIENT_ID), { body: commands.map(c=>c.toJSON()) });
        console.log("[Bot] Slash commands registered");
    } catch(e) { console.error("[Bot] Failed to register commands:", e); }
});

// Auto-reconnect on disconnect
client.on("disconnect", () => {
    console.log("[Bot] Disconnected, reconnecting...");
    setTimeout(() => client.login(process.env.DISCORD_BOT_TOKEN), 3000);
});
client.on("error", err => console.error("[Bot] Error:", err));

client.login(process.env.DISCORD_BOT_TOKEN).catch(err => {
    console.error("[Bot] Login failed:", err.message);
    setTimeout(() => client.login(process.env.DISCORD_BOT_TOKEN), 5000);
});
