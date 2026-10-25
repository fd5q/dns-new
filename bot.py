import asyncio
import hmac
import json
import logging
import os
from pathlib import Path

from aiohttp import web
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Required environment variables:
# BOT_TOKEN=your Telegram bot token
# ADMIN_CHAT_ID=your numeric Telegram chat ID
# PUBLIC_BASE_URL=https://your-public-host.example
# WEBHOOK_SECRET=a-long-random-secret
#
# Optional:
# PROFILE_PATH=/path/to/iPad_Basic_DNS_Protection.mobileconfig
# PORT=8080

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("security-bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_CHAT_ID_RAW = os.getenv("ADMIN_CHAT_ID", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
PORT = int(os.getenv("PORT", "8080"))

PROFILE_PATH = Path(
    os.getenv(
        "PROFILE_PATH",
        str(Path(__file__).with_name("iPad_Basic_DNS_Protection.mobileconfig")),
    )
)

if not BOT_TOKEN:
    raise RuntimeError("Set BOT_TOKEN in your hosting environment.")
if not ADMIN_CHAT_ID_RAW:
    raise RuntimeError("Set ADMIN_CHAT_ID to your numeric Telegram chat ID.")
if not PUBLIC_BASE_URL.startswith("https://"):
    raise RuntimeError("Set PUBLIC_BASE_URL to your public HTTPS hosting URL.")
if len(WEBHOOK_SECRET) < 24:
    raise RuntimeError("Set WEBHOOK_SECRET to a random secret of at least 24 characters.")

try:
    ADMIN_CHAT_ID = int(ADMIN_CHAT_ID_RAW)
except ValueError as exc:
    raise RuntimeError("ADMIN_CHAT_ID must be a numeric Telegram chat ID.") from exc

PROFILE_URL = f"{PUBLIC_BASE_URL}/profile"


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [[InlineKeyboardButton("⬇️ تحميل ملف الحماية", url=PROFILE_URL)]]
    text = (
        "🛡️ بوت ملف حماية الآيباد\n\n"
        "اضغط الزر لتحميل ملف إعداد DNS.\n\n"
        "تنبيه: ملف الإعداد لا يكتشف التجسس ولا يراقب الآيباد بنفسه. "
        "التنبيهات الأمنية تصل فقط إذا ربطت مصدر مراقبة فعليًا بعنوان webhook الخاص بهذا البوت."
    )
    if update.message:
        await update.message.reply_text(
            text, reply_markup=InlineKeyboardMarkup(keyboard)
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(
            "الأوامر:\n/start — رابط تحميل الملف\n/help — هذه المساعدة\n\n"
            "التنبيهات تُرسل للمسؤول فقط عند وصول حدث موثوق إلى /security-event."
        )


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def download_profile(request: web.Request) -> web.StreamResponse:
    if not PROFILE_PATH.is_file():
        return web.json_response(
            {"error": "Configuration profile file is missing on the server."},
            status=404,
        )
    return web.FileResponse(
        path=PROFILE_PATH,
        headers={
            "Content-Type": "application/x-apple-aspen-config",
            "Content-Disposition": 'attachment; filename="iPad_Basic_DNS_Protection.mobileconfig"',
            "X-Content-Type-Options": "nosniff",
        },
    )


async def security_event(request: web.Request) -> web.Response:
    supplied_secret = request.headers.get("X-Webhook-Secret", "")
    if not hmac.compare_digest(supplied_secret, WEBHOOK_SECRET):
        return web.json_response({"error": "unauthorized"}, status=401)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return web.json_response({"error": "invalid JSON"}, status=400)

    if not isinstance(data, dict):
        return web.json_response({"error": "JSON object required"}, status=400)

    # Keep alerts short and avoid echoing arbitrary large/sensitive payloads.
    event = str(data.get("event", "Unspecified security event"))[:500]
    device = str(data.get("device", "Unknown device"))[:120]
    severity = str(data.get("severity", "unknown"))[:40]
    source = str(data.get("source", "Connected monitoring source"))[:120]

    message = (
        "⚠️ تنبيه أمني من مصدر مراقبة متصل\n\n"
        f"الخطورة: {severity}\n"
        f"الجهاز: {device}\n"
        f"المصدر: {source}\n"
        f"الحدث: {event}\n\n"
        "ملاحظة: هذا تنبيه وارد من المصدر المتصل، وليس فحصًا مستقلًا من البوت."
    )

    app: Application = request.app["telegram_application"]
    try:
        await app.bot.send_message(chat_id=ADMIN_CHAT_ID, text=message)
    except Exception:
        logger.exception("Failed to send security event to Telegram")
        return web.json_response({"error": "could not deliver Telegram alert"}, status=502)

    return web.json_response({"status": "alert sent"})


async def main() -> None:
    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))

    await application.initialize()
    await application.start()
    if application.updater is None:
        raise RuntimeError("Telegram updater is unavailable.")
    await application.updater.start_polling()

    web_app = web.Application(client_max_size=16 * 1024)
    web_app["telegram_application"] = application
    web_app.router.add_get("/", health)
    web_app.router.add_get("/health", health)
    web_app.router.add_get("/profile", download_profile)
    web_app.router.add_post("/security-event", security_event)

    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=PORT)
    await site.start()

    logger.info("Bot polling started; web server listening on port %s", PORT)
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
        await application.updater.stop()
        await application.stop()
        await application.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
