import discord
from discord import app_commands
from discord.ext import commands
import os
import re
from motor.motor_asyncio import AsyncIOMotorClient

# --- MongoDB Setup ------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI not set in environment variables!")

mongo = AsyncIOMotorClient(MONGO_URI)
db = mongo["AntiSuspiciousBot"]
guilds_col = db["guilds"]
warnings_col = db["warnings"]

DEFAULT_CONFIG = {
    "language": "fr",
    "protection_level": "standard",
    "custom_links": [],
    "ignored_channels": [],
    "ignored_roles": [],
}

# Seuils kick/ban
KICK_THRESHOLD = 5   # kick apres 5 liens
BAN_THRESHOLD = 3    # ban apres 3 liens supplementaires post-kick

async def get_guild_config(guild_id: int) -> dict:
    doc = await guilds_col.find_one({"_id": guild_id})
    if doc is None:
        doc = {"_id": guild_id, **DEFAULT_CONFIG}
        await guilds_col.insert_one(doc)
    for k, v in DEFAULT_CONFIG.items():
        if k not in doc:
            doc[k] = v
    return doc

async def update_guild_config(guild_id: int, key: str, value):
    await guilds_col.update_one(
        {"_id": guild_id},
        {"$set": {key: value}},
        upsert=True,
    )

async def increment_warnings(guild_id: int, user_id: int) -> dict:
    """
    Incremente le compteur d'avertissements.
    Retourne le doc mis a jour : {total, post_kick}
    - total    : nombre total de liens envoyes
    - post_kick: liens envoyes APRES le premier kick (remis a 0 au kick)
    """
    doc = await warnings_col.find_one_and_update(
        {"guild_id": guild_id, "user_id": user_id},
        {"$inc": {"total": 1, "post_kick": 1}},
        upsert=True,
        return_document=True,
    )
    # find_one_and_update avec upsert peut retourner None sur creation initiale
    if doc is None:
        doc = await warnings_col.find_one({"guild_id": guild_id, "user_id": user_id})
    return doc

async def reset_post_kick(guild_id: int, user_id: int):
    """Remet le compteur post-kick a 0 apres un kick."""
    await warnings_col.update_one(
        {"guild_id": guild_id, "user_id": user_id},
        {"$set": {"post_kick": 0}},
    )

async def get_warnings(guild_id: int, user_id: int) -> dict:
    doc = await warnings_col.find_one({"guild_id": guild_id, "user_id": user_id})
    if doc is None:
        return {"total": 0, "post_kick": 0}
    return doc

# --- Link Databases -----------------------------------------------
STANDARD_LINKS = [
    "grabify.link", "location.cyou", "mymap.icu", "mymap.quest",
    "map-s.online", "crypto-o.click", "cryp-o.online", "account.beauty",
    "photospace.life", "photovault.store", "imagehub.fun", "sharevault.cloud",
    "xtube.chat", "screensnaps.top", "foot.wiki", "screenshare.pics",
    "shrekis.life", "gamingfun.me", "stopify.co",
]

FULL_LINKS = STANDARD_LINKS + [
    "iplogger.org", "iplogger.com", "maper.info", "iplogger.co",
    "2no.co", "yip.su", "iplogger.info", "iplog.co", "iplogger.cn",
    "grabify.org", "urlto.me", "onbit.pro", "snifferip.com", "unl.one",
    "discord-nitro.gift", "discordnitro.gift", "discordgift.site",
    "discord-gift.site", "discordapp-gifts.com", "discordapp-nitro.com",
    "discord-airdrop.com", "discordfree-nitro.com", "discord-claim.net",
    "discord-event.com", "discordpromo.net", "discordbonus.gift",
    "discordreward.net", "discordgiftcenter.com", "discordpresent.com",
    "dlscord.com", "d1scord.com", "disc0rd.com", "discorcl.com",
    "discordd.com", "discordapp-login.com", "discordlogin.net",
    "discord-security.net", "discordverify.com", "discord-verification.com",
    "discord-auth.net", "steam-discord.com", "steamgift-event.com",
    "steamcommunity-gift.com", "steamreward.net", "steamnitro.com",
    "free-steam-items.com", "csgo-drop.xyz", "skin-giveaway.net", "steambonusgift.com",
    "grabify.link", "iplogger.org", "iplogger.com", "2no.co", "yip.su",
    "blasze.com", "bmab.ru", "ip-track.net", "ipgrabber.ru", "trackerlink.org",
    "bit.ly", "tinyurl.com", "cutt.ly", "shorturl.at", "rebrand.ly",
    "t.co", "goo.su", "is.gd", "discord-verify.com", "discord-supportteam.com",
    "discordstaff.net", "discordappeal.com", "discordbanappeal.net", "discordhelpdesk.org",
    "discord-airdrop.net", "nft-discorddrop.com", "crypto-nitro.net",
    "eth-gift-event.com", "airdropbonus.xyz", "cryptogift-event.net"
]

def _clean_domain(raw: str) -> str:
    return (
        raw.lower()
        .replace("https://", "")
        .replace("http://", "")
        .replace("www.", "")
        .split("/")[0]
        .strip()
    )

def extract_domains(text: str) -> list[str]:
    pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:/[^\s]*)?'
    return [m.lower() for m in re.findall(pattern, text)]

async def check_message(content: str, guild_id: int) -> tuple[str | None, str]:
    gc = await get_guild_config(guild_id)
    level = gc.get("protection_level", "standard")
    custom = [_clean_domain(l) for l in gc.get("custom_links", [])]

    if level == "full":
        blocked = [_clean_domain(d) for d in FULL_LINKS]
    elif level == "custom_only":
        blocked = []
    else:
        blocked = [_clean_domain(d) for d in STANDARD_LINKS]

    domains = extract_domains(content)

    for domain in domains:
        for b in blocked:
            if domain == b or domain.endswith("." + b):
                return "ip_grabber", domain
        for c in custom:
            if domain == c or domain.endswith("." + c):
                return "custom", domain

    return None, ""

# --- Translations -------------------------------------------------
T = {
    "fr": {
        # Avertissements dans le chat
        "ip_grabber_warn": "🚨 {mention}, vous avez envoyé un **IP Grabber** ! Votre message a été supprimé. ({count}/{threshold})",
        "custom_warn": "⚠️ {mention}, vous avez envoyé un **lien suspect** ! Votre message a été supprimé. ({count}/{threshold})",
        "kicked_msg": "🦵 {mention} a été **expulsé** du serveur après avoir envoyé {n} liens interdits.",
        "banned_msg": "🔨 {mention} a été **banni définitivement** pour envoi de liens interdits.",
        "kick_reason": "Envoi de liens interdits",
        "ban_reason": "Envoi de liens interdits",
        # /config
        "config_title": "⚙️ Configuration — AntiSuspiciousBot",
        "config_desc": "Gérez les paramètres du bot pour ce serveur.",
        "config_lang_field": "🌐 Langue",
        "config_lang_value": "Changer la langue du bot",
        "config_sec_field": "🛡️ Sécurité",
        "config_sec_value": "Gérer la protection anti-liens suspects",
        "config_footer": "AntiSuspiciousBot • Visible uniquement par vous",
        # Boutons ConfigView
        "btn_language": "🌐 Langue",
        "btn_security": "🛡️ Sécurité",
        "btn_view_config": "📋 Voir la Config",
        # SecurityView
        "sec_title": "🛡️ Sécurité",
        "sec_level": "Niveau",
        "sec_custom": "Liens bloqués personnalisés",
        "sec_channels": "Salons ignorés",
        "sec_roles": "Rôles ignorés",
        "sec_none": "`Aucun`",
        "btn_add_link": "➕ Ajouter un lien",
        "btn_remove_link": "➖ Retirer un lien",
        "btn_ignore_channel": "🔇 Ignorer un salon",
        "btn_ignore_role": "🔕 Ignorer un rôle",
        "btn_remove_ignored": "✏️ Retirer une exception",
        # Protection select
        "select_placeholder": "Choisir le niveau de protection…",
        "protection_set": "✅ Niveau de protection défini sur **{level}**.",
        # Modals
        "modal_add_link_title": "Ajouter un lien bloqué",
        "modal_add_link_label": "Lien",
        "modal_add_link_placeholder": "ex: grabify.link ou https://example.com",
        "modal_remove_link_title": "Retirer un lien bloqué",
        "modal_remove_link_label": "Lien à retirer",
        "modal_ignore_channel_title": "Ignorer un salon",
        "modal_ignore_role_title": "Ignorer un rôle",
        "modal_remove_ignored_title": "Retirer une exception (salon ou rôle)",
        "modal_id_label": "ID du salon",
        "modal_role_id_label": "ID du rôle",
        "modal_remove_id_label": "ID du salon ou du rôle",
        # Réponses modals
        "custom_added": "✅ Lien `{link}` ajouté à la liste de blocage.",
        "custom_removed": "✅ Lien `{link}` retiré de la liste.",
        "custom_not_found": "❌ Lien `{link}` introuvable dans la liste.",
        "channel_ignored": "✅ Salon <#{cid}> ajouté aux exceptions.",
        "role_ignored": "✅ Rôle <@&{rid}> ajouté aux exceptions.",
        "removed_ok": "✅ ID `{iid}` retiré des exceptions.",
        "removed_not_found": "❌ ID `{iid}` introuvable dans les exceptions.",
        "no_link": "❌ Veuillez entrer un lien valide.",
        "invalid_id": "❌ ID invalide.",
        # Vue config actuelle
        "current_config": (
            "📋 **Configuration actuelle**\n"
            "- Langue : `{lang}`\n"
            "- Protection : `{level}`\n"
            "- Liens bloqués custom : `{custom_count}`\n"
            "- Salons ignorés : {channels}\n"
            "- Rôles ignorés : {roles}"
        ),
        "none": "Aucun",
    },
    "en": {
        # Chat warnings
        "ip_grabber_warn": "🚨 {mention}, you sent an **IP Grabber**! Your message has been deleted. ({count}/{threshold})",
        "custom_warn": "⚠️ {mention}, you sent a **suspicious link**! Your message has been deleted. ({count}/{threshold})",
        "kicked_msg": "🦵 {mention} has been **kicked** from the server after sending {n} censored links.",
        "banned_msg": "🔨 {mention} has been **permanently banned** for sending censored links.",
        "kick_reason": "Censored links sent",
        "ban_reason": "Censored links sent",
        # /config
        "config_title": "⚙️ Configuration — AntiSuspiciousBot",
        "config_desc": "Manage bot settings for this server.",
        "config_lang_field": "🌐 Language",
        "config_lang_value": "Change the bot language",
        "config_sec_field": "🛡️ Security",
        "config_sec_value": "Manage suspicious link protection",
        "config_footer": "AntiSuspiciousBot • Only visible to you",
        # Config buttons
        "btn_language": "🌐 Language",
        "btn_security": "🛡️ Security",
        "btn_view_config": "📋 View Config",
        # SecurityView
        "sec_title": "🛡️ Security",
        "sec_level": "Level",
        "sec_custom": "Custom blocked links",
        "sec_channels": "Ignored channels",
        "sec_roles": "Ignored roles",
        "sec_none": "`None`",
        "btn_add_link": "➕ Add custom link",
        "btn_remove_link": "➖ Remove custom link",
        "btn_ignore_channel": "🔇 Ignore channel",
        "btn_ignore_role": "🔕 Ignore role",
        "btn_remove_ignored": "✏️ Remove exception",
        # Protection select
        "select_placeholder": "Choose protection level…",
        "protection_set": "✅ Protection level set to **{level}**.",
        # Modals
        "modal_add_link_title": "Add custom blocked link",
        "modal_add_link_label": "Link",
        "modal_add_link_placeholder": "ex: grabify.link or https://example.com",
        "modal_remove_link_title": "Remove custom blocked link",
        "modal_remove_link_label": "Link to remove",
        "modal_ignore_channel_title": "Ignore a channel",
        "modal_ignore_role_title": "Ignore a role",
        "modal_remove_ignored_title": "Remove ignored channel or role",
        "modal_id_label": "Channel ID",
        "modal_role_id_label": "Role ID",
        "modal_remove_id_label": "Channel or Role ID",
        # Modal responses
        "custom_added": "✅ Link `{link}` added to block list.",
        "custom_removed": "✅ Link `{link}` removed from list.",
        "custom_not_found": "❌ Link `{link}` not found in the list.",
        "channel_ignored": "✅ Channel <#{cid}> added to exceptions.",
        "role_ignored": "✅ Role <@&{rid}> added to exceptions.",
        "removed_ok": "✅ ID `{iid}` removed from exceptions.",
        "removed_not_found": "❌ ID `{iid}` not found in exceptions.",
        "no_link": "❌ Please enter a valid link.",
        "invalid_id": "❌ Invalid ID.",
        # View config
        "current_config": (
            "📋 **Current configuration**\n"
            "- Language: `{lang}`\n"
            "- Protection: `{level}`\n"
            "- Custom blocked links: `{custom_count}`\n"
            "- Ignored channels: {channels}\n"
            "- Ignored roles: {roles}"
        ),
        "none": "None",
    },
}

def tl(_lang: str, key: str, **kwargs) -> str:
    """Traduction synchrone avec une langue deja connue."""
    text = T.get(_lang, T["fr"]).get(key, key)
    return text.format(**kwargs)

async def t(guild_id: int, key: str, **kwargs) -> str:
    """Traduction asynchrone avec lookup de la langue en base."""
    gc = await get_guild_config(guild_id)
    lang = gc.get("language", "fr")
    return tl(lang, key, **kwargs)

# --- Bot Setup ----------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# --- on_guild_join ------------------------------------------------
@bot.event
async def on_guild_join(guild: discord.Guild):
    channel = None
    for ch in guild.text_channels:
        if ch.permissions_for(guild.me).send_messages:
            channel = ch
            break
    if not channel:
        return

    await get_guild_config(guild.id)

    embed = discord.Embed(
        title="👋 Merci de m'avoir invité ! / Thanks for inviting me!",
        description="Choisissez la langue du bot / Choose the bot language:",
        color=0x5865F2,
    )
    embed.set_footer(text="AntiSuspiciousBot")
    await channel.send(embed=embed, view=LanguageSelectView(guild.id, initial=True))

# --- Message Scanner ----------------------------------------------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    gc = await get_guild_config(message.guild.id)

    if message.channel.id in gc.get("ignored_channels", []):
        return

    author_role_ids = [r.id for r in message.author.roles]
    if any(rid in author_role_ids for rid in gc.get("ignored_roles", [])):
        return

    category, domain = await check_message(message.content, message.guild.id)
    if not category:
        await bot.process_commands(message)
        return

    # Supprimer le message
    try:
        await message.delete()
    except discord.Forbidden:
        pass

    lang = gc.get("language", "fr")
    mention = message.author.mention
    guild = message.guild
    member = message.author

    # Incrementer les avertissements
    warn_doc = await increment_warnings(guild.id, member.id)
    total = warn_doc.get("total", 1)
    post_kick = warn_doc.get("post_kick", 1)

    # Determiner si on est en mode "post-kick" (a deja ete kick)
    already_kicked = warn_doc.get("kicked", False)

    if already_kicked:
        # Mode post-kick : on compte vers le ban
        threshold = BAN_THRESHOLD
        count = post_kick
    else:
        # Mode normal : on compte vers le kick
        threshold = KICK_THRESHOLD
        count = total

    # Envoyer l'avertissement avec compteur
    key = "ip_grabber_warn" if category == "ip_grabber" else "custom_warn"
    warn = tl(lang, key, mention=mention, count=count, threshold=threshold)
    await message.channel.send(warn)

    # Verifier si on atteint le seuil
    if already_kicked and post_kick >= BAN_THRESHOLD:
        # BAN
        try:
            ban_reason = tl(lang, "ban_reason")
            await guild.ban(member, reason=ban_reason, delete_message_days=0)
            ban_msg = tl(lang, "banned_msg", mention=mention)
            await message.channel.send(ban_msg)
        except discord.Forbidden:
            pass

    elif not already_kicked and total >= KICK_THRESHOLD:
        # KICK
        try:
            kick_reason = tl(lang, "kick_reason")
            await guild.kick(member, reason=kick_reason)
            kick_msg = tl(lang, "kicked_msg", mention=mention, n=KICK_THRESHOLD)
            await message.channel.send(kick_msg)
            # Marquer comme kick et remettre post_kick a 0
            await warnings_col.update_one(
                {"guild_id": guild.id, "user_id": member.id},
                {"$set": {"kicked": True, "post_kick": 0}},
            )
        except discord.Forbidden:
            pass

    await bot.process_commands(message)

# --- Views --------------------------------------------------------
class LanguageSelectView(discord.ui.View):
    def __init__(self, guild_id: int, initial: bool = False):
        super().__init__(timeout=300)
        self.guild_id = guild_id
        self.initial = initial

    @discord.ui.button(label="🇫🇷 Français", style=discord.ButtonStyle.primary)
    async def set_fr(self, interaction: discord.Interaction, button: discord.ui.Button):
        await update_guild_config(self.guild_id, "language", "fr")
        embed = discord.Embed(description="✅ Langue définie sur **Français**.", color=0x57F287)
        await interaction.response.edit_message(embed=embed, view=None)

    @discord.ui.button(label="🇬🇧 English", style=discord.ButtonStyle.primary)
    async def set_en(self, interaction: discord.Interaction, button: discord.ui.Button):
        await update_guild_config(self.guild_id, "language", "en")
        embed = discord.Embed(description="✅ Language set to **English**.", color=0x57F287)
        await interaction.response.edit_message(embed=embed, view=None)


class ProtectionSelect(discord.ui.Select):
    def __init__(self, guild_id: int, lang: str):
        self.guild_id = guild_id
        options = [
            discord.SelectOption(label="Standard", value="standard", emoji="🛡️",
                description="IP grabbers courants" if lang == "fr" else "Common IP grabbers"),
            discord.SelectOption(label="Full Protection", value="full", emoji="🔒",
                description="Liste étendue" if lang == "fr" else "Extended block list"),
            discord.SelectOption(label="Custom Only", value="custom_only", emoji="⚙️",
                description="Vos liens uniquement" if lang == "fr" else "Only your custom links"),
        ]
        placeholder = tl(lang, "select_placeholder")
        super().__init__(placeholder=placeholder, options=options)

    async def callback(self, interaction: discord.Interaction):
        await update_guild_config(self.guild_id, "protection_level", self.values[0])
        labels = {"standard": "Standard 🛡️", "full": "Full Protection 🔒", "custom_only": "Custom Only ⚙️"}
        msg = await t(self.guild_id, "protection_set", level=labels.get(self.values[0], self.values[0]))
        await interaction.response.send_message(msg, ephemeral=True)


class SecurityView(discord.ui.View):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(timeout=180)
        self.guild_id = guild_id
        self.lang = lang
        self.add_item(ProtectionSelect(guild_id, lang))

    @discord.ui.button(style=discord.ButtonStyle.success, row=1)
    async def add_link(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(AddLinkModal(self.guild_id, self.lang))

    @discord.ui.button(style=discord.ButtonStyle.danger, row=1)
    async def remove_link(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(RemoveLinkModal(self.guild_id, self.lang))

    @discord.ui.button(style=discord.ButtonStyle.secondary, row=2)
    async def ignore_chan(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IgnoreChannelModal(self.guild_id, self.lang))

    @discord.ui.button(style=discord.ButtonStyle.secondary, row=2)
    async def ignore_role(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(IgnoreRoleModal(self.guild_id, self.lang))

    @discord.ui.button(style=discord.ButtonStyle.secondary, row=3)
    async def remove_ignored(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(RemoveIgnoredModal(self.guild_id, self.lang))

    def set_labels(self):
        """Applique les labels traduits apres la creation de la vue."""
        buttons = [c for c in self.children if isinstance(c, discord.ui.Button)]
        labels = [
            tl(self.lang, "btn_add_link"),
            tl(self.lang, "btn_remove_link"),
            tl(self.lang, "btn_ignore_channel"),
            tl(self.lang, "btn_ignore_role"),
            tl(self.lang, "btn_remove_ignored"),
        ]
        for btn, label in zip(buttons, labels):
            btn.label = label


class ConfigView(discord.ui.View):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(timeout=180)
        self.guild_id = guild_id
        self.lang = lang
        # Labels traduits
        for child in self.children:
            if isinstance(child, discord.ui.Button):
                if child.custom_id and "lang" in child.custom_id:
                    child.label = tl(lang, "btn_language")
                elif child.custom_id and "sec" in child.custom_id:
                    child.label = tl(lang, "btn_security")
                elif child.custom_id and "cfg" in child.custom_id:
                    child.label = tl(lang, "btn_view_config")

    @discord.ui.button(custom_id="lang", style=discord.ButtonStyle.secondary, row=0)
    async def lang_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = discord.Embed(
            title="🌐 Langue / Language",
            description="Choisissez la langue / Choose language:",
            color=0x5865F2,
        )
        await interaction.response.send_message(embed=embed, view=LanguageSelectView(self.guild_id), ephemeral=True)

    @discord.ui.button(custom_id="sec", style=discord.ButtonStyle.danger, row=0)
    async def security_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        gc = await get_guild_config(self.guild_id)
        lang = gc.get("language", "fr")
        level = gc.get("protection_level", "standard")
        custom = gc.get("custom_links", [])
        channels = gc.get("ignored_channels", [])
        roles = gc.get("ignored_roles", [])

        none_str = tl(lang, "sec_none")
        ch_str = ", ".join(f"<#{c}>" for c in channels) or none_str
        role_str = ", ".join(f"<@&{r}>" for r in roles) or none_str
        custom_str = "\n".join(f"• `{l}`" for l in custom) or none_str

        embed = discord.Embed(title=tl(lang, "sec_title"), color=0xED4245)
        embed.add_field(name=tl(lang, "sec_level"), value=f"`{level}`", inline=True)
        embed.add_field(name=tl(lang, "sec_custom"), value=custom_str, inline=False)
        embed.add_field(name=tl(lang, "sec_channels"), value=ch_str, inline=False)
        embed.add_field(name=tl(lang, "sec_roles"), value=role_str, inline=False)

        view = SecurityView(self.guild_id, lang)
        view.set_labels()
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    @discord.ui.button(custom_id="cfg", style=discord.ButtonStyle.primary, row=1)
    async def view_cfg(self, interaction: discord.Interaction, button: discord.ui.Button):
        gc = await get_guild_config(self.guild_id)
        lang = gc.get("language", "fr")
        level = gc.get("protection_level", "standard")
        custom = gc.get("custom_links", [])
        channels = gc.get("ignored_channels", [])
        roles = gc.get("ignored_roles", [])

        none_str = tl(lang, "none")
        ch_str = ", ".join(f"<#{c}>" for c in channels) if channels else none_str
        role_str = ", ".join(f"<@&{r}>" for r in roles) if roles else none_str

        msg = tl(lang, "current_config",
            lang=lang.upper(), level=level,
            custom_count=len(custom),
            channels=ch_str, roles=role_str,
        )
        await interaction.response.send_message(msg, ephemeral=True)

    def apply_labels(self):
        for child in self.children:
            if isinstance(child, discord.ui.Button):
                if child.custom_id == "lang":
                    child.label = tl(self.lang, "btn_language")
                elif child.custom_id == "sec":
                    child.label = tl(self.lang, "btn_security")
                elif child.custom_id == "cfg":
                    child.label = tl(self.lang, "btn_view_config")


# --- Modals -------------------------------------------------------
class AddLinkModal(discord.ui.Modal):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(title=tl(lang, "modal_add_link_title"))
        self.guild_id = guild_id
        self.lang = lang
        self.link = discord.ui.TextInput(
            label=tl(lang, "modal_add_link_label"),
            placeholder=tl(lang, "modal_add_link_placeholder"),
            max_length=200,
        )
        self.add_item(self.link)

    async def on_submit(self, interaction: discord.Interaction):
        raw = self.link.value.strip()
        if not raw:
            await interaction.response.send_message(tl(self.lang, "no_link"), ephemeral=True)
            return
        await guilds_col.update_one(
            {"_id": self.guild_id},
            {"$addToSet": {"custom_links": raw}},
            upsert=True,
        )
        await interaction.response.send_message(tl(self.lang, "custom_added", link=raw), ephemeral=True)


class RemoveLinkModal(discord.ui.Modal):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(title=tl(lang, "modal_remove_link_title"))
        self.guild_id = guild_id
        self.lang = lang
        self.link = discord.ui.TextInput(
            label=tl(lang, "modal_remove_link_label"),
            placeholder="ex: grabify.link",
            max_length=200,
        )
        self.add_item(self.link)

    async def on_submit(self, interaction: discord.Interaction):
        raw = self.link.value.strip()
        result = await guilds_col.update_one(
            {"_id": self.guild_id},
            {"$pull": {"custom_links": raw}},
        )
        if result.modified_count:
            msg = tl(self.lang, "custom_removed", link=raw)
        else:
            msg = tl(self.lang, "custom_not_found", link=raw)
        await interaction.response.send_message(msg, ephemeral=True)


class IgnoreChannelModal(discord.ui.Modal):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(title=tl(lang, "modal_ignore_channel_title"))
        self.guild_id = guild_id
        self.lang = lang
        self.channel_id = discord.ui.TextInput(
            label=tl(lang, "modal_id_label"),
            placeholder="ex: 123456789012345678",
            max_length=25,
        )
        self.add_item(self.channel_id)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            cid = int(self.channel_id.value.strip())
        except ValueError:
            await interaction.response.send_message(tl(self.lang, "invalid_id"), ephemeral=True)
            return
        await guilds_col.update_one(
            {"_id": self.guild_id},
            {"$addToSet": {"ignored_channels": cid}},
            upsert=True,
        )
        await interaction.response.send_message(tl(self.lang, "channel_ignored", cid=cid), ephemeral=True)


class IgnoreRoleModal(discord.ui.Modal):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(title=tl(lang, "modal_ignore_role_title"))
        self.guild_id = guild_id
        self.lang = lang
        self.role_id = discord.ui.TextInput(
            label=tl(lang, "modal_role_id_label"),
            placeholder="ex: 123456789012345678",
            max_length=25,
        )
        self.add_item(self.role_id)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            rid = int(self.role_id.value.strip())
        except ValueError:
            await interaction.response.send_message(tl(self.lang, "invalid_id"), ephemeral=True)
            return
        await guilds_col.update_one(
            {"_id": self.guild_id},
            {"$addToSet": {"ignored_roles": rid}},
            upsert=True,
        )
        await interaction.response.send_message(tl(self.lang, "role_ignored", rid=rid), ephemeral=True)


class RemoveIgnoredModal(discord.ui.Modal):
    def __init__(self, guild_id: int, lang: str):
        super().__init__(title=tl(lang, "modal_remove_ignored_title"))
        self.guild_id = guild_id
        self.lang = lang
        self.item_id = discord.ui.TextInput(
            label=tl(lang, "modal_remove_id_label"),
            placeholder="ex: 123456789012345678",
            max_length=25,
        )
        self.add_item(self.item_id)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            iid = int(self.item_id.value.strip())
        except ValueError:
            await interaction.response.send_message(tl(self.lang, "invalid_id"), ephemeral=True)
            return
        result = await guilds_col.update_one(
            {"_id": self.guild_id},
            {"$pull": {"ignored_channels": iid, "ignored_roles": iid}},
        )
        if result.modified_count:
            msg = tl(self.lang, "removed_ok", iid=iid)
        else:
            msg = tl(self.lang, "removed_not_found", iid=iid)
        await interaction.response.send_message(msg, ephemeral=True)


# --- Slash Commands -----------------------------------------------
@tree.command(name="config", description="Configure AntiSuspiciousBot for this server")
@app_commands.default_permissions(manage_guild=True)
async def config_cmd(interaction: discord.Interaction):
    gid = interaction.guild_id
    gc = await get_guild_config(gid)
    lang = gc.get("language", "fr")

    embed = discord.Embed(
        title=tl(lang, "config_title"),
        description=tl(lang, "config_desc"),
        color=0x5865F2,
    )
    embed.add_field(name=tl(lang, "config_lang_field"), value=tl(lang, "config_lang_value"), inline=False)
    embed.add_field(name=tl(lang, "config_sec_field"), value=tl(lang, "config_sec_value"), inline=False)
    embed.set_footer(text=tl(lang, "config_footer"))

    view = ConfigView(gid, lang)
    view.apply_labels()
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


# --- Ready --------------------------------------------------------
@bot.event
async def on_ready():
    await tree.sync()
    print(f"✅ {bot.user} connecté. Slash commands synchronisées.")
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="suspicious links 🔍"
        )
    )


# --- Run ----------------------------------------------------------
TOKEN = os.environ.get("DISCORD_TOKEN")
if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN not set in environment variables!")

bot.run(TOKEN)
