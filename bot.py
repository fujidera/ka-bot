"""Telegram-бот проверки cookie kleinanzeigen.de.

- Цикл: 6 часов работы → 1 минута паузы → снова старт.
- Логи шифруются (Fernet), автоудаляются по TTL, лежат ВНЕ репозитория.
- Без ALLOWED_USER_IDS бот пускает только ADMIN_ID (fail-closed).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatAction, ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import Message
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from checker import CheckResult, check_cookies, load_cookies_from_bytes

# ---------------------------------------------------------------------------
# Конфиг
# ---------------------------------------------------------------------------

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN не задан в .env")

ADMIN_ID_RAW = os.getenv("ADMIN_ID", "").strip()
ADMIN_ID: int | None = int(ADMIN_ID_RAW) if ADMIN_ID_RAW else None

_allowed = os.getenv("ALLOWED_USER_IDS", "").strip()
ALLOWED_USER_IDS: set[int] = (
    {int(x) for x in _allowed.split(",") if x.strip()} if _allowed else set()
)

LOG_DIR = Path(os.getenv("LOG_DIR", "/var/lib/ka-bot/logs")).resolve()
LOG_DIR.mkdir(parents=True, exist_ok=True)

ENCRYPTION_KEY = os.getenv("LOG_ENCRYPTION_KEY", "").strip()
if not ENCRYPTION_KEY:
    raise SystemExit("LOG_ENCRYPTION_KEY не задан в .env")
cipher = Fernet(ENCRYPTION_KEY.encode())

MAX_FILE_SIZE = 1 * 1024 * 1024
LOG_TTL_HOURS = int(os.getenv("LOG_TTL_HOURS", "72"))

WORK_SECONDS = 6 * 60 * 60   # 6 часов
SLEEP_SECONDS = 60           # 1 минута

# ---------------------------------------------------------------------------
# Логирование (только stdout, без сырых кук)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("ka-bot")

# ---------------------------------------------------------------------------
# Бот
# ---------------------------------------------------------------------------

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)
dp = Dispatcher()
router = Router()
dp.include_router(router)

# ---------------------------------------------------------------------------
# Хелперы
# ---------------------------------------------------------------------------

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str, max_len: int = 60) -> str:
    base = Path(name).name
    safe = _SAFE_NAME_RE.sub("_", base)
    if not safe.lower().endswith(".json"):
        safe += ".json"
    if len(safe) > max_len:
        safe = safe[: max_len - 5] + ".json"
    return safe or "upload.json"


def save_encrypted_upload(
    raw: bytes,
    *,
    user_id: int,
    username: str | None,
    first_name: str | None,
    chat_id: int,
    original_name: str,
) -> Path:
    now = datetime.now(timezone.utc)
    day_dir = LOG_DIR / now.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)

    safe_name = sanitize_filename(original_name)
    stem = now.strftime("%H%M%S") + f"_{user_id}_{safe_name}"
    file_path = day_dir / (stem + ".enc")
    file_path.write_bytes(cipher.encrypt(raw))

    meta = {
        "received_at": now.isoformat(),
        "user_id": user_id,
        "username": username,
        "first_name": first_name,
        "chat_id": chat_id,
        "original_filename": original_name,
        "saved_filename": file_path.name,
        "size_bytes": len(raw),
        "encrypted": True,
        "result": None,
    }
    (day_dir / (stem + ".meta.json")).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return file_path


def update_meta_result(file_path: Path, result: CheckResult) -> None:
    meta_path = file_path.with_suffix(file_path.suffix + ".meta.json")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        log.exception("meta read failed: %s", meta_path)
        return

    meta["result"] = {
        "status": result.status,
        "reason": result.reason,
        "http_code": result.http_code,
        "final_url": result.final_url,
        "cookies": [
            {
                "name": c.name,
                "expired": c.is_expired(),
                "expires": c.expires,
                "secure": c.secure,
                "http_only": c.http_only,
                "same_site": c.same_site,
                "domain": c.domain,
            }
            for c in result.cookies
        ],
    }
    try:
        meta_path.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        log.exception("meta write failed: %s", meta_path)


def cleanup_old_logs() -> None:
    cutoff = time.time() - LOG_TTL_HOURS * 3600
    for p in LOG_DIR.rglob("*"):
        if p.is_file() and p.stat().st_mtime < cutoff:
            try:
                p.unlink()
            except OSError:
                log.exception("cleanup failed: %s", p)


def is_admin(user_id: int | None) -> bool:
    return ADMIN_ID is not None and user_id == ADMIN_ID


def is_allowed(user_id: int | None) -> bool:
    if not ALLOWED_USER_IDS:
        return is_admin(user_id)   # fail-closed
    return user_id in ALLOWED_USER_IDS


# ---------------------------------------------------------------------------
# Формат ответа
# ---------------------------------------------------------------------------

ICONS = {"valid": "✅", "expired": "⏰", "unauthorized": "❌", "unknown": "❓"}
TITLES = {
    "valid": "Сессия активна",
    "expired": "Истёк срок действия кук",
    "unauthorized": "Сервер не признал сессию",
    "unknown": "Не удалось определить",
}


def format_result(
    filename: str,
    r: CheckResult,
    saved_path: Path | None = None,
    *,
    show_saved_path: bool = False,
) -> str:
    lines = [
        f"{ICONS.get(r.status, '•')} <b>{TITLES.get(r.status, r.status)}</b>",
        f"📄 <code>{filename}</code>",
    ]
    if r.http_code is not None:
        lines.append(f"🌐 HTTP: <code>{r.http_code}</code>")
    if r.reason:
        lines.append(f"ℹ️ {r.reason}")
    if r.final_url:
        lines.append(f"🔗 <code>{r.final_url}</code>")

    if r.cookies:
        lines.append("")
        lines.append(f"🍪 Кук: <b>{len(r.cookies)}</b>")
        for c in r.cookies:
            flags = []
            if c.secure:
                flags.append("Secure")
            if c.http_only:
                flags.append("HttpOnly")
            if c.same_site:
                flags.append(f"SameSite={c.same_site}")
            flags_str = f" [{', '.join(flags)}]" if flags else ""
            mark = " ⏰" if c.is_expired() else ""
            lines.append(
                f"• <code>{c.name}</code>{flags_str}{mark}\n"
                f"   expires: {c.expires_human}"
            )

    if show_saved_path and saved_path is not None:
        lines.append("")
        lines.append(f"💾 <code>{saved_path}</code>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Хендлеры
# ---------------------------------------------------------------------------

@router.message(CommandStart())
async def cmd_start(msg: Message):
    if not is_allowed(msg.from_user.id):
        await msg.answer("⛔ Доступ запрещён.")
        return
    await msg.answer(
        "👋 <b>Привет!</b>\n\n"
        "Я проверяю валидность cookie <b>kleinanzeigen.de</b>.\n\n"
        "📎 Пришлите JSON-файл с куками (Cookie-Editor → Export → JSON).\n\n"
        "⚠️ Отправляйте <b>только свои</b> куки.\n\n"
        "Команды: /help"
    )


@router.message(Command("help"))
async def cmd_help(msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    await msg.answer(
        "📖 <b>Как экспортировать куки</b>\n\n"
        "1. Установите <b>Cookie-Editor</b>.\n"
        "2. Зайдите на kleinanzeigen.de под своим аккаунтом.\n"
        "3. Cookie-Editor → <b>Export</b> → <b>JSON</b>.\n"
        "4. Пришлите файл боту.\n\n"
        "⚠️ Не отправляйте куки посторонним."
    )


@router.message(F.document)
async def on_document(msg: Message):
    if not is_allowed(msg.from_user.id):
        return

    doc = msg.document
    if not doc.file_name or not doc.file_name.lower().endswith(".json"):
        await msg.answer("⚠️ Пришлите JSON-файл.")
        return
    if (doc.file_size or 0) > MAX_FILE_SIZE:
        await msg.answer("⚠️ Файл слишком большой (>1 МБ).")
        return

    await bot.send_chat_action(msg.chat.id, ChatAction.TYPING)

    try:
        buf = await bot.download(doc)
        raw = buf.read()
    except Exception as e:
        log.exception("download failed")
        await msg.answer(f"❌ Не удалось скачать файл: {e}")
        return

    u = msg.from_user
    log.info("Upload from user_id=%s file=%s size=%d", u.id, doc.file_name, len(raw))

    saved_path: Path | None = None
    try:
        saved_path = save_encrypted_upload(
            raw,
            user_id=u.id,
            username=u.username,
            first_name=u.first_name,
            chat_id=msg.chat.id,
            original_name=doc.file_name,
        )
    except Exception:
        log.exception("save_encrypted_upload failed")

    try:
        cookies = load_cookies_from_bytes(raw)
    except Exception as e:
        await msg.answer(f"❌ Не могу разобрать JSON: {e}")
        return

    result = await asyncio.to_thread(check_cookies, cookies)

    if saved_path is not None:
        update_meta_result(saved_path, result)

    cleanup_old_logs()

    await msg.answer(format_result(
        doc.file_name,
        result,
        saved_path,
        show_saved_path=is_admin(u.id),
    ))


@router.message(F.text)
async def fallback(msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    await msg.answer("Отправьте JSON-файл с куками. Инструкция: /help")


# ---------------------------------------------------------------------------
# Цикл 6ч работы → 1м паузы
# ---------------------------------------------------------------------------

async def _stop_after(seconds: int) -> None:
    await asyncio.sleep(seconds)
    log.info("Time limit reached (%d sec), stopping polling", seconds)
    await dp.stop_polling()


async def polling_cycle() -> None:
    while True:
        log.info("Polling start (max %d sec)", WORK_SECONDS)
        stop_task = asyncio.create_task(_stop_after(WORK_SECONDS))
        try:
            await dp.start_polling(bot, handle_signals=False)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Polling crashed")
        finally:
            stop_task.cancel()
            try:
                await stop_task
            except asyncio.CancelledError:
                pass
        log.info("Polling stopped, sleep %d sec", SLEEP_SECONDS)
        await asyncio.sleep(SLEEP_SECONDS)


async def main() -> None:
    log.info("Bot started. Log dir: %s (encrypted)", LOG_DIR)
    if ADMIN_ID:
        log.info("Admin ID: %s", ADMIN_ID)
    else:
        log.warning("ADMIN_ID не задан — админ-функции отключены")
    if not ALLOWED_USER_IDS:
        log.warning("ALLOWED_USER_IDS пуст — бот работает только для админа (fail-closed)")
    else:
        log.info("Whitelist active: %s", ALLOWED_USER_IDS)
    await polling_cycle()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Bot stopped")
