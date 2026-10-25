import asyncio
import hmac
import json
import logging
import os
import plistlib
from pathlib import Path

from aiohttp import web
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

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
        "أرسل ملف .mobileconfig هنا لفحص أولي لإعداداته.\n"
        "التنبيهات الأمنية تصل من مصدر مراقبة خارجي مربوط بالـ webhook فقط.\n\n"
        "مهم: البوت لا يراقب الآيباد ولا يكتشف كل برامج التجسس."
    )
    if update.message:
        await update.message.reply_text(
            text, reply_markup=InlineKeyboardMarkup(keyboard)
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(
            "الأوامر:\n/start — رابط تحميل الملف\n/help — هذه المساعدة\n\n"
            "أرسل ملف .mobileconfig هنا لفحص أولي.\n"
            "التنبيهات الخارجية: POST /security-event مع ترويسة X-Webhook-Secret.\n"
            "هذا لا يراقب الآيباد مباشرةً ولا يثبت أن الملف آمن."
        )



def inspect_mobileconfig(raw: bytes) -> tuple[str, list[str]]:
    """Basic static review only; this does not prove a profile is safe or malicious."""
    findings: list[str] = []
    try:
        data = plistlib.loads(raw)
    except Exception:
        return "تعذر قراءة الملف كملف إعدادات Apple صالح (plist).", [
            "قد يكون الملف تالفًا أو ليس ملف mobileconfig حقيقيًا."
        ]

    if not isinstance(data, dict):
        return "بنية الملف غير متوقعة.", ["لم يكن المحتوى قاموس إعدادات Apple."]

    payloads = data.get("PayloadContent", [])
    if not isinstance(payloads, list):
        payloads = []
        findings.append("بنية PayloadContent غير معتادة.")

    types = []
    for item in payloads:
        if not isinstance(item, dict):
            continue
        ptype = str(item.get("PayloadType", "Unknown"))
        types.append(ptype)
        if "webcontent-filter" in ptype.lower() or "contentfilter" in ptype.lower():
            findings.append("يحتوي على حمولة فلتر محتوى؛ قد تتطلب إعدادات خاصة أو إشرافًا حسب نوعها.")
        if "certificate" in ptype.lower() and "root" in ptype.lower():
            findings.append("يتضمن نوع حمولة متعلقًا بشهادة جذر؛ تحقق من مصدرها قبل التثبيت.")
        if "vpn" in ptype.lower():
            findings.append("يتضمن إعداد VPN؛ تحقق من الخادم والجهة التي تديره.")
        if "dnssettings" in ptype.lower():
            findings.append("يتضمن إعدادات DNS.")
        if "com.apple.mdm" in ptype.lower():
            findings.append("يتضمن حمولة إدارة جهاز (MDM)؛ لا تثبته إلا إذا كنت تثق بالجهة المسؤولة.")

    label = str(data.get("PayloadDisplayName", "غير محدد"))[:120]
    org = str(data.get("PayloadOrganization", "غير محددة"))[:120]
    summary = [f"اسم الملف: {label}", f"الجهة المعلنة: {org}", f"أنواع الحمولات: {', '.join(types) if types else 'لم يتم العثور على حمولات واضحة'}"]
    if not findings:
        findings.append("لم تُكتشف مؤشرات من القواعد البسيطة، لكن هذا لا يثبت أن الملف آمن.")
    return "\n".join(summary), findings


async def scan_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message
    if not message or not message.document:
        return
    doc = message.document
    filename = (doc.file_name or "").lower()
    if not filename.endswith(".mobileconfig"):
        await message.reply_text("أرسل ملفًا بامتداد .mobileconfig لفحص إعداداته. لا أستطيع فحص الجهاز نفسه.")
        return
    if doc.file_size and doc.file_size > 1024 * 1024:
        await message.reply_text("حجم الملف أكبر من 1 ميغابايت؛ ارسل نسخة أصغر للفحص.")
        return
    try:
        tg_file = await doc.get_file()
        raw = bytes(await tg_file.download_as_bytearray())
        summary, findings = inspect_mobileconfig(raw)
        result = ("🔎 نتيجة فحص أولي لملف الإعدادات\n\n" + summary + "\n\n" +
                  "ملاحظات:\n" + "\n".join(f"• {item}" for item in findings) +
                  "\n\nهذا فحص ثابت محدود؛ لا يكشف كل المخاطر ولا يفحص الآيباد نفسه.")
        await message.reply_text(result[:4000])
        if update.effective_user and update.effective_user.id != ADMIN_CHAT_ID:
            # No copy of the uploaded file is stored or forwarded to the administrator.
            await context.bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text=f"ℹ️ تم فحص ملف mobileconfig من مستخدم للبوت.\nالنتيجة: {'توجد ملاحظات للمراجعة' if len(findings) > 1 or 'غير معتادة' in findings[0] else 'لم تظهر مؤشرات بالقواعد البسيطة'}."
            )
    except Exception:
        logger.exception("Failed to scan uploaded profile")
        await message.reply_text("تعذر فحص الملف. تأكد أنه ملف mobileconfig صالح وحاول مرة أخرى.")


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
    application.add_handler(MessageHandler(filters.Document.ALL, scan_document))

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
