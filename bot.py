
import os
import re
import json
import time
import sqlite3
import logging
import hashlib
import secrets
import asyncio
from pathlib import Path
from datetime import datetime, timezone

from aiohttp import web
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup
)
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    CallbackQueryHandler, ContextTypes, filters
)

# ================= CONFIG =================

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_CHAT_ID = int(os.environ["ADMIN_CHAT_ID"])
PUBLIC_BASE_URL = os.environ.get(
    "PUBLIC_BASE_URL", "https://dns.xx805303.workers.dev"
).rstrip("/")
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]
ADMIN_CODE = os.environ.get("ADMIN_CODE", "06931e3q")
DB_PATH = os.environ.get("DB_PATH", "bot.db")
PORT = int(os.environ.get("PORT", "10000"))

if len(WEBHOOK_SECRET) < 24:
    raise RuntimeError("WEBHOOK_SECRET must be at least 24 characters.")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("security-bot")

# ================= DATABASE =================

def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            uid INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            joined INTEGER,
            last_seen INTEGER,
            blocked INTEGER DEFAULT 0,
            password_ok INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER,
            actor INTEGER,
            action TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS support (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid INTEGER,
            ts INTEGER,
            direction TEXT,
            body TEXT
        );
        """)
        defaults = {
            "locked": "0",
            "maintenance": "0",
            "password_enabled": "0",
            "password_hash": "",
        }
        for k, v in defaults.items():
            c.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",
                (k, v)
            )

def setting(key):
    with db() as c:
        r = c.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return r["value"] if r else ""

def set_setting(key, value):
    with db() as c:
        c.execute("""
            INSERT INTO settings(key,value) VALUES(?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """, (key, str(value)))

def log_action(actor, action, detail=""):
    with db() as c:
        c.execute(
            "INSERT INTO logs(ts,actor,action,detail) VALUES(?,?,?,?)",
            (int(time.time()), actor, action, str(detail)[:1000])
        )

def remember_user(user):
    now = int(time.time())
    with db() as c:
        c.execute("""
            INSERT INTO users(uid,username,first_name,joined,last_seen)
            VALUES(?,?,?,?,?)
            ON CONFLICT(uid) DO UPDATE SET
              username=excluded.username,
              first_name=excluded.first_name,
              last_seen=excluded.last_seen
        """, (
            user.id, user.username or "", user.first_name or "",
            now, now
        ))

def user_is_blocked(uid):
    with db() as c:
        r = c.execute(
            "SELECT blocked FROM users WHERE uid=?", (uid,)
        ).fetchone()
        return bool(r and r["blocked"])

def is_admin(update):
    u = update.effective_user
    return bool(u and u.id == ADMIN_CHAT_ID)

def password_ok(uid):
    with db() as c:
        r = c.execute(
            "SELECT password_ok FROM users WHERE uid=?", (uid,)
        ).fetchone()
        return bool(r and r["password_ok"])

def allowed(update):
    u = update.effective_user
    if not u:
        return False
    if u.id == ADMIN_CHAT_ID:
        return True
    if user_is_blocked(u.id):
        return False
    if setting("locked") == "1":
        return False
    if setting("maintenance") == "1":
        return False
    if setting("password_enabled") == "1" and not password_ok(u.id):
        return False
    return True

# Temporary interaction state; reset when the process restarts.
pending = {}
admin_sessions = set()
support_reply_to = {}

# ================= KEYBOARDS =================

def admin_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔒 قفل البوت", callback_data="lock"),
            InlineKeyboardButton("🔓 فتح البوت", callback_data="unlock")
        ],
        [
            InlineKeyboardButton("🛠 الصيانة", callback_data="maintenance"),
            InlineKeyboardButton("📊 الإحصائيات", callback_data="stats")
        ],
        [
            InlineKeyboardButton("👥 المستخدمون", callback_data="users"),
            InlineKeyboardButton("📜 سجل الإدارة", callback_data="logs")
        ],
        [
            InlineKeyboardButton("🚫 حظر مستخدم", callback_data="ban"),
            InlineKeyboardButton("✅ فك الحظر", callback_data="unban")
        ],
        [
            InlineKeyboardButton("🔑 تغيير كلمة المرور", callback_data="setpass"),
            InlineKeyboardButton("🔐 تشغيل/إيقاف كلمة المرور", callback_data="pass_toggle")
        ],
        [
            InlineKeyboardButton("📢 رسالة للجميع", callback_data="broadcast"),
            InlineKeyboardButton("✉️ مراسلة شخص", callback_data="dm")
        ],
        [
            InlineKeyboardButton("🧪 فحص ملف إعدادات", callback_data="scan_help"),
            InlineKeyboardButton("🌐 رابط DNS", callback_data="dns")
        ],
        [
            InlineKeyboardButton("❌ إلغاء العملية", callback_data="cancel")
        ]
    ])

async def show_admin(update, context):
    if update.effective_user.id != ADMIN_CHAT_ID:
        return
    admin_sessions.add(ADMIN_CHAT_ID)
    msg = (
        "🛡 لوحة التحكم\n\n"
        f"حالة البوت: {'مقفل 🔒' if setting('locked') == '1' else 'مفتوح 🔓'}\n"
        f"الصيانة: {'مفعلة' if setting('maintenance') == '1' else 'متوقفة'}\n"
        f"كلمة المرور: {'مفعلة' if setting('password_enabled') == '1' else 'متوقفة'}"
    )
    if update.callback_query:
        await update.callback_query.edit_message_text(
            msg, reply_markup=admin_keyboard()
        )
    else:
        await update.effective_message.reply_text(
            msg, reply_markup=admin_keyboard()
        )

# ================= USER COMMANDS =================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    remember_user(u)

    if u.id == ADMIN_CHAT_ID:
        await update.message.reply_text(
            "مرحبًا بالمدير. اكتب admin لفتح لوحة التحكم."
        )
        return

    if user_is_blocked(u.id):
        await update.message.reply_text("🚫 لا يمكنك استخدام هذا البوت.")
        return

    if setting("locked") == "1":
        await update.message.reply_text("البوت مقفل 🔒")
        return

    if setting("maintenance") == "1":
        await update.message.reply_text("🛠 البوت تحت الصيانة. حاول لاحقًا.")
        return

    if setting("password_enabled") == "1" and not password_ok(u.id):
        pending[u.id] = {"action": "user_password"}
        await update.message.reply_text("🔐 أرسل كلمة مرور البوت للمتابعة.")
        return

    await update.message.reply_text(
        "أهلًا بك!\n"
        "الأوامر:\n"
        "/start - البداية\n"
        "/help - المساعدة\n"
        "/dns - رابط DNS\n"
        "/support - مراسلة مدير البوت"
    )

async def help_cmd(update, context):
    await update.message.reply_text(
        "الأوامر المتاحة:\n"
        "/start - بدء الاستخدام\n"
        "/dns - رابط DNS\n"
        "/support - التواصل مع المدير\n"
        "/cancel - إلغاء العملية"
    )

async def dns_cmd(update, context):
    if not allowed(update):
        await gate_message(update)
        return
    await update.message.reply_text(f"🌐 رابط DNS:\n{PUBLIC_BASE_URL}")

async def support_cmd(update, context):
    u = update.effective_user
    remember_user(u)
    if not allowed(update):
        await gate_message(update)
        return
    pending[u.id] = {"action": "support"}
    await update.message.reply_text(
        "اكتب رسالتك للمدير الآن. أرسل /cancel للإلغاء."
    )

async def cancel_cmd(update, context):
    uid = update.effective_user.id
    pending.pop(uid, None)
    support_reply_to.pop(uid, None)
    await update.message.reply_text("تم إلغاء العملية.")

async def gate_message(update):
    uid = update.effective_user.id
    if user_is_blocked(uid):
        msg = "🚫 تم منعك من استخدام البوت."
    elif setting("locked") == "1":
        msg = "البوت مقفل 🔒"
    elif setting("maintenance") == "1":
        msg = "🛠 البوت تحت الصيانة. حاول لاحقًا."
    elif setting("password_enabled") == "1" and not password_ok(uid):
        msg = "🔐 أرسل /start ثم أدخل كلمة المرور."
    else:
        msg = "لا يمكن تنفيذ الطلب حاليًا."
    await update.effective_message.reply_text(msg)

# ================= ADMIN AUTH =================

async def admin_text(update, context):
    u = update.effective_user
    if not u:
        return
    remember_user(u)

    text = (update.message.text or "").strip()

    if u.id == ADMIN_CHAT_ID and text.lower() == "admin":
        pending[u.id] = {"action": "admin_code"}
        await update.message.reply_text("🔐 أرسل الكود للتحقق:")
        return

    state = pending.get(u.id, {})
    action = state.get("action")

    if action == "admin_code" and u.id == ADMIN_CHAT_ID:
        if secrets.compare_digest(text, ADMIN_CODE):
            pending.pop(u.id, None)
            admin_sessions.add(u.id)
            log_action(u.id, "admin_login", "verified")
            await show_admin(update, context)
        else:
            pending.pop(u.id, None)
            await update.message.reply_text("❌ الكود غير صحيح.")
        return

    if u.id == ADMIN_CHAT_ID and u.id in admin_sessions:
        if action == "ban" or action == "unban":
            if not text.isdigit():
                await update.message.reply_text("أرسل Telegram ID رقميًا.")
                return
            target = int(text)
            with db() as c:
                c.execute("""
                    INSERT OR IGNORE INTO users(uid,username,first_name,joined,last_seen)
                    VALUES(?,?,?,?,?)
                """, (target, "", "", int(time.time()), int(time.time())))
                c.execute(
                    "UPDATE users SET blocked=? WHERE uid=?",
                    (1 if action == "ban" else 0, target)
                )
            log_action(u.id, action, target)
            pending.pop(u.id, None)
            await update.message.reply_text("تم تنفيذ العملية.")
            return

        if action == "setpass":
            if len(text) < 6:
                await update.message.reply_text(
                    "اجعل كلمة المرور 6 أحرف على الأقل."
                )
                return
            digest = hashlib.sha256(text.encode()).hexdigest()
            set_setting("password_hash", digest)
            set_setting("password_enabled", "1")
            pending.pop(u.id, None)
            log_action(u.id, "set_password")
            await update.message.reply_text("تم تغيير كلمة المرور وتفعيلها.")
            return

        if action == "broadcast":
            pending.pop(u.id, None)
            with db() as c:
                ids = [r["uid"] for r in c.execute(
                    "SELECT uid FROM users WHERE blocked=0 AND uid!=?",
                    (ADMIN_CHAT_ID,)
                )]
            ok, fail = 0, 0
            status = await update.message.reply_text("جارٍ إرسال الرسائل...")
            for target in ids:
                try:
                    await context.bot.send_message(target, text)
                    ok += 1
                except Exception:
                    fail += 1
                await asyncio.sleep(0.04)
            log_action(u.id, "broadcast", f"sent={ok}, failed={fail}")
            await status.edit_text(
                f"انتهى الإرسال.\nنجح: {ok}\nتعذر: {fail}"
            )
            return

        if action == "dm":
            parts = text.split(maxsplit=1)
            if len(parts) < 2 or not parts[0].isdigit():
                await update.message.reply_text(
                    "أرسل: رقم_المستخدم ثم مسافة ثم الرسالة."
                )
                return
            target = int(parts[0])
            body = parts[1]
            try:
                await context.bot.send_message(
                    target, "✉️ رسالة من مدير البوت:\n" + body
                )
                with db() as c:
                    c.execute(
                        "INSERT INTO support(uid,ts,direction,body) VALUES(?,?,?,?)",
                        (target, int(time.time()), "admin_to_user", body)
                    )
                log_action(u.id, "dm", target)
                await update.message.reply_text("تم إرسال الرسالة.")
            except Exception as e:
                await update.message.reply_text(
                    "تعذر الإرسال. قد يكون المستخدم لم يبدأ البوت أو حظره."
                )
            pending.pop(u.id, None)
            return

        if action == "reply":
            target = state.get("target")
            try:
                await context.bot.send_message(
                    target, "💬 رد من مدير البوت:\n" + text
                )
                with db() as c:
                    c.execute(
                        "INSERT INTO support(uid,ts,direction,body) VALUES(?,?,?,?)",
                        (target, int(time.time()), "admin_reply", text)
                    )
                await update.message.reply_text("تم إرسال الرد.")
            except Exception:
                await update.message.reply_text("تعذر إرسال الرد.")
            pending.pop(u.id, None)
            return

    # User password entry
    if action == "user_password":
        expected = setting("password_hash")
        digest = hashlib.sha256(text.encode()).hexdigest()
        if expected and secrets.compare_digest(digest, expected):
            with db() as c:
                c.execute("UPDATE users SET password_ok=1 WHERE uid=?", (u.id,))
            pending.pop(u.id, None)
            await update.message.reply_text("✅ تم التحقق. أرسل /start.")
        else:
            await update.message.reply_text("❌ كلمة المرور غير صحيحة.")
        return

    # User support message
    if action == "support":
        pending.pop(u.id, None)
        body = text[:3500]
        with db() as c:
            c.execute(
                "INSERT INTO support(uid,ts,direction,body) VALUES(?,?,?,?)",
                (u.id, int(time.time()), "user_to_admin", body)
            )
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton(
                "↩️ الرد على المستخدم", callback_data=f"reply:{u.id}"
            )
        ]])
        await context.bot.send_message(
            ADMIN_CHAT_ID,
            f"📩 رسالة من مستخدم\n"
            f"الاسم: {u.first_name or '-'}\n"
            f"المعرف: @{u.username or '-'}\n"
            f"ID: {u.id}\n\n{body}",
            reply_markup=kb
        )
        await update.message.reply_text("تم إرسال رسالتك للمدير.")
        return

    if u.id != ADMIN_CHAT_ID and not allowed(update):
        await gate_message(update)

# ================= ADMIN CALLBACKS =================

async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.from_user.id != ADMIN_CHAT_ID:
        await q.answer("غير مصرح.", show_alert=True)
        return

    if q.from_user.id not in admin_sessions:
        await q.message.reply_text("اكتب admin ثم أدخل رمز التحقق.")
        return

    data = q.data

    if data == "cancel":
        pending.pop(ADMIN_CHAT_ID, None)
        await q.edit_message_text("تم إلغاء العملية.")
        return

    if data == "lock":
        set_setting("locked", "1")
        log_action(ADMIN_CHAT_ID, "lock")
        await show_admin(update, context)
    elif data == "unlock":
        set_setting("locked", "0")
        log_action(ADMIN_CHAT_ID, "unlock")
        await show_admin(update, context)
    elif data == "maintenance":
        val = "0" if setting("maintenance") == "1" else "1"
        set_setting("maintenance", val)
        log_action(ADMIN_CHAT_ID, "maintenance", val)
        await show_admin(update, context)
    elif data == "pass_toggle":
        val = "0" if setting("password_enabled") == "1" else "1"
        set_setting("password_enabled", val)
        log_action(ADMIN_CHAT_ID, "password_toggle", val)
        await show_admin(update, context)
    elif data == "setpass":
        pending[ADMIN_CHAT_ID] = {"action": "setpass"}
        await q.message.reply_text("أرسل كلمة المرور الجديدة (6 أحرف على الأقل).")
    elif data == "ban":
        pending[ADMIN_CHAT_ID] = {"action": "ban"}
        await q.message.reply_text("أرسل Telegram ID للمستخدم المراد حظره.")
    elif data == "unban":
        pending[ADMIN_CHAT_ID] = {"action": "unban"}
        await q.message.reply_text("أرسل Telegram ID لفك الحظر.")
    elif data == "broadcast":
        pending[ADMIN_CHAT_ID] = {"action": "broadcast"}
        await q.message.reply_text("أرسل نص الرسالة الجماعية.")
    elif data == "dm":
        pending[ADMIN_CHAT_ID] = {"action": "dm"}
        await q.message.reply_text(
            "أرسل رقم المستخدم ثم مسافة ثم الرسالة."
        )
    elif data == "reply":
        await show_admin(update, context)
    elif data.startswith("reply:"):
        target = int(data.split(":", 1)[1])
        pending[ADMIN_CHAT_ID] = {"action": "reply", "target": target}
        await q.message.reply_text(
            f"اكتب الرد الذي تريد إرساله للمستخدم {target}."
        )
    elif data == "dns":
        await q.message.reply_text(f"رابط DNS:\n{PUBLIC_BASE_URL}")
    elif data == "scan_help":
        await q.message.reply_text(
            "أرسل ملف .mobileconfig إلى البوت لفحص بعض إعداداته."
        )
    elif data == "stats":
        with db() as c:
            total = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            blocked = c.execute(
                "SELECT COUNT(*) n FROM users WHERE blocked=1"
            ).fetchone()["n"]
            recent = c.execute(
                "SELECT COUNT(*) n FROM users WHERE last_seen>=?",
                (int(time.time()) - 86400,)
            ).fetchone()["n"]
        await q.message.reply_text(
            f"📊 الإحصائيات\nالمستخدمون: {total}\n"
            f"المحظورون: {blocked}\nنشطون آخر 24 ساعة: {recent}"
        )
    elif data == "users":
        with db() as c:
            rows = c.execute(
                "SELECT uid,username,first_name,blocked,last_seen "
                "FROM users ORDER BY last_seen DESC LIMIT 30"
            ).fetchall()
        if not rows:
            await q.message.reply_text("لا يوجد مستخدمون مسجلون بعد.")
        else:
            lines = ["👥 آخر المستخدمين (حتى 30):"]
            for r in rows:
                lines.append(
                    f"{r['first_name'] or '-'} | @{r['username'] or '-'} | "
                    f"ID {r['uid']} | {'محظور' if r['blocked'] else 'مسموح'}"
                )
            await q.message.reply_text("\n".join(lines)[:4000])
    elif data == "logs":
        with db() as c:
            rows = c.execute(
                "SELECT ts,actor,action,detail FROM logs ORDER BY id DESC LIMIT 15"
            ).fetchall()
        lines = ["📜 آخر العمليات:"]
        for r in rows:
            dt = datetime.fromtimestamp(r["ts"]).strftime("%m-%d %H:%M")
            lines.append(f"{dt} | {r['actor']} | {r['action']} | {r['detail']}")
        await q.message.reply_text("\n".join(lines)[:4000])

# ================= MOBILECONFIG SCAN =================

SUSPICIOUS_KEYS = [
    "PayloadType", "PayloadIdentifier", "PayloadDisplayName",
    "DNSSettings", "DNSProtocol", "ServerAddresses",
    "VPN", "WebContentFilter", "ContentFilterUUID",
    "PayloadRemovalDisallowed", "Certificate", "SCEP",
    "com.apple.security", "com.apple.vpn"
]

async def scan_document(update, context):
    u = update.effective_user
    remember_user(u)

    if u.id != ADMIN_CHAT_ID and not allowed(update):
        await gate_message(update)
        return

    doc = update.message.document
    if not doc:
        return
    name = doc.file_name or "unknown"
    if not name.lower().endswith(".mobileconfig"):
        await update.message.reply_text(
            "أرسل ملفًا ينتهي اسمه بـ .mobileconfig."
        )
        return

    if doc.file_size and doc.file_size > 1_000_000:
        await update.message.reply_text("الملف كبير جدًا للفحص.")
        return

    tgfile = await context.bot.get_file(doc.file_id)
    data = await tgfile.download_as_bytearray()
    raw = bytes(data)

    # Avoid interpreting XML as executable code.
    text = raw.decode("utf-8", errors="replace")
    hits = [key for key in SUSPICIOUS_KEYS if key.lower() in text.lower()]
    payloads = re.findall(r"<key>PayloadType</key>\s*<string>(.*?)</string>", text)
    identifiers = re.findall(
        r"<key>PayloadIdentifier</key>\s*<string>(.*?)</string>", text
    )

    report = [
        "🔎 نتيجة الفحص الأولي",
        f"الملف: {name}",
        f"الحجم: {len(raw)} bytes",
        f"PayloadType: {', '.join(payloads[:10]) or 'لم يُستخرج'}",
        f"Identifiers: {', '.join(identifiers[:10]) or 'لم يُستخرج'}",
        f"مفاتيح إعدادات ذات صلة: {', '.join(hits) or 'لم تُطابق القائمة'}",
        "",
        "⚠️ هذا فحص نصي أولي فقط، ولا يثبت أن الملف آمن أو ضار."
    ]
    await update.message.reply_text("\n".join(report)[:4000])

    if u.id != ADMIN_CHAT_ID:
        await context.bot.send_message(
            ADMIN_CHAT_ID,
            f"🧪 فُحص ملف إعدادات من المستخدم {u.id} (@{u.username or '-'})\n"
            f"الملف: {name}\n"
            f"مفاتيح ملحوظة: {', '.join(hits) or 'لا توجد مطابقات'}"
        )

# ================= EXTERNAL SECURITY WEBHOOK =================

async def health(request):
    return web.json_response({"status": "ok"})

async def security_event(request):
    supplied = request.headers.get("X-Webhook-Secret", "")
    if not secrets.compare_digest(supplied, WEBHOOK_SECRET):
        raise web.HTTPUnauthorized(text="Unauthorized")

    try:
        payload = await request.json()
    except Exception:
        raise web.HTTPBadRequest(text="Expected JSON")

    # Accept only simple event fields; never execute received content.
    event = str(payload.get("event", "Security event"))[:200]
    details = str(payload.get("details", ""))[:2000]
    severity = str(payload.get("severity", "unknown"))[:50]

    await request.app["bot"].send_message(
        ADMIN_CHAT_ID,
        f"🚨 تنبيه أمني وارد\nالحدث: {event}\n"
        f"الخطورة: {severity}\nالتفاصيل: {details}"
    )
    return web.json_response({"received": True})

async def root(request):
    return web.json_response({
        "service": "security-bot",
        "status": "running",
        "note": "This service does not directly monitor your iPad."
    })

# ================= APP STARTUP =================

async def post_init(app: Application):
    init_db()
    app.bot_data["started"] = True

    webapp = web.Application()
    webapp["bot"] = app.bot
    webapp.router.add_get("/", root)
    webapp.router.add_get("/health", health)
    webapp.router.add_post("/security-event", security_event)

    runner = web.AppRunner(webapp)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    app.bot_data["web_runner"] = runner
    log.info("Web server listening on %s", PORT)

async def post_shutdown(app: Application):
    runner = app.bot_data.get("web_runner")
    if runner:
        await runner.cleanup()

def main():
    init_db()
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("dns", dns_cmd))
    app.add_handler(CommandHandler("support", support_cmd))
    app.add_handler(CommandHandler("cancel", cancel_cmd))
    app.add_handler(CallbackQueryHandler(admin_callback))
    app.add_handler(MessageHandler(filters.Document.ALL, scan_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, admin_text))

    log.info("Starting Telegram bot")
    app.run_polling(drop_pending_updates=False)

if __name__ == "__main__":
    main()
