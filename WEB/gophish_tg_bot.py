import asyncio
import json
import logging
from pathlib import Path
from datetime import datetime, timezone

import aiohttp
from telegram import Bot


# Settings
GOPHISH_URL = "https://<GOPHISH_URL>:3333"
GOPHISH_API_KEY = "GOPHISH_API_KEY"
TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "CHAT_ID"

CHECK_INTERVAL = 5
VERIFY_TLS = False
STATE_FILE = Path("gophish_state.json")

TRACKED_EVENTS = {
    "email opened",
    "clicked link",
    "submitted data",
}


# Logs
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger("gophish-monitor")


# State
def load_state():
    try:
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(state, dict):
                return state

    except Exception:
        log.exception("Не удалось прочитать state-файл")

    return {}


def save_state(state):
    tmp = STATE_FILE.with_suffix(".tmp")

    tmp.write_text(
        json.dumps(state, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    tmp.replace(STATE_FILE)


# Gophish API
async def gophish_get(session, endpoint):
    async with session.get(
        GOPHISH_URL.rstrip("/") + endpoint,
        headers={"Authorization": GOPHISH_API_KEY},
        ssl=VERIFY_TLS,
        timeout=aiohttp.ClientTimeout(total=15)
    ) as r:

        if r.status != 200:
            raise RuntimeError(
                f"Gophish HTTP {r.status}: {await r.text()}"
            )

        return await r.json()


# Telegram
async def send_telegram(bot, message):
    try:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=message,
            parse_mode="HTML",
            disable_web_page_preview=True
        )
        return True

    except Exception:
        log.exception("ОШИБКА TELEGRAM: сообщение не отправлено")
        return False


# Helpers
def escape_html(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def format_time(value):
    if not value:
        return "неизвестно"

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        dt = dt.astimezone()

        return dt.strftime("%d.%m.%Y %H:%M:%S")

    except Exception:
        return value


def parse_details(raw):
    if isinstance(raw, dict):
        return raw

    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


def flatten(value):
    return ", ".join(map(str, value)) if isinstance(value, list) else str(value or "")


def normalize_status(value):
    return str(value or "").strip().lower()


# Message
def make_message(campaign, result):
    status = normalize_status(result.get("status"))
    email = result.get("email", "unknown")

    name = (
        f"{result.get('first_name', '')} "
        f"{result.get('last_name', '')}"
    ).strip() or email

    titles = {
        "email opened": "✉️ <b>Письмо открыто</b>",
        "clicked link": "🔗 <b>Ссылка открыта</b>",
        "submitted data": "🔐 <b>Данные отправлены</b>"
    }

    title = titles.get(
        status,
        f"ℹ️ <b>{escape_html(result.get('status', 'Unknown'))}</b>"
    )

    lines = [
        title,
        "",
        (
            f"Кампания: <b>{escape_html(campaign.get('name', f'Campaign #{campaign.get('id')}'))}</b>"
        ),
        f"Пользователь: <b>{escape_html(name)}</b>",
        f"Email: <code>{escape_html(email)}</code>",
        (
            f"Время: <code>{escape_html(format_time(result.get('modified_date')))}</code>"
        )
    ]

    details = parse_details(result.get("details"))

    if details:
        browser = details.get("browser") or {}

        if isinstance(browser, dict):
            for label, value in (
                ("IP", browser.get("address")),
                ("User-Agent", browser.get("user-agent"))
            ):
                if value:
                    lines.append(
                        f"{label}: <code>{escape_html(value)}</code>"
                    )

        payload = details.get("payload") or {}

        if (
            status == "submitted data"
            and isinstance(payload, dict)
            and payload
        ):
            lines.extend(["", "<b>Данные формы:</b>"])

            lines.extend(
                f"{escape_html(k)}: <code>{escape_html(flatten(v))}</code>"
                for k, v in payload.items()
            )

    return "\n".join(lines)


# Timeline
def is_tracked_event(event):
    return normalize_status(event.get("message")) in TRACKED_EVENTS


def event_key(campaign_id, event):
    """
    Ключ отдельного события.
    Повторные события одного email имеют разные timestamps.
    """
    return "|".join((
        str(campaign_id),
        str(event.get("email") or "").lower(),
        str(event.get("time") or ""),
        normalize_status(event.get("message"))
    ))


def initialize_timeline_state(campaigns, state):
    """
    Первый запуск новой версии:
    запоминаем уже существующие события, не отправляя историю в Telegram.
    """
    known_events = set()

    for campaign in campaigns:
        cid = campaign.get("id")

        for event in campaign.get("timeline", []) or []:
            if is_tracked_event(event):
                known_events.add(event_key(cid, event))

    state["timeline_events"] = list(known_events)
    state["initialized"] = True

    save_state(state)

    log.info(
        "Первичная инициализация: сохранено событий: %s",
        len(known_events)
    )


def find_recipient(campaign, email):
    email = (email or "").lower()

    for result in campaign.get("results", []) or []:
        if (result.get("email") or "").lower() == email:
            return result

    return {}


# Processing
async def process_campaigns(session, bot, state):
    campaigns = await gophish_get(session, "/api/campaigns/")

    if not state.get("initialized"):
        initialize_timeline_state(campaigns, state)
        return

    known_events = set(state.get("timeline_events", []))

    new_events = []

    for campaign in campaigns:
        cid = campaign.get("id")

        for event in campaign.get("timeline", []) or []:
            if not is_tracked_event(event):
                continue

            key = event_key(cid, event)

            if key in known_events:
                continue

            new_events.append((key, event, campaign))

    new_events.sort(
        key=lambda item: item[1].get("time") or ""
    )

    for key, event, campaign in new_events:
        cname = campaign.get("name", campaign.get("id"))
        email = event.get("email", "unknown")

        recipient = find_recipient(campaign, email)

        event_result = {
            **recipient,
            "email": email,
            "status": event.get("message", ""),
            "modified_date": event.get("time", ""),
            "details": event.get("details", "")
        }

        message = make_message(campaign, event_result)

        log.info(
            "[%s] Новое событие: %s | %s | %s",
            cname,
            email,
            event.get("message"),
            event.get("time")
        )

        # Если Telegram не отправил сообщение, останавливаем обработку, чтобы сохранить порядок событий
        if not await send_telegram(bot, message):
            log.error(
                "[%s] Telegram не отправил событие. "
                "State НЕ обновляем. Повторим при следующем опросе.",
                cname
            )
            break

        # Отмечаем событие обработанным только после отправки
        known_events.add(key)

        state["timeline_events"] = list(known_events)
        save_state(state)

        log.info(
            "[%s] Событие успешно отправлено: %s",
            cname,
            email
        )


# Main
async def main():
    for value, placeholder in (
        (GOPHISH_API_KEY, "GOPHISH_API_KEY"),
        (TELEGRAM_BOT_TOKEN, "TELEGRAM_BOT_TOKEN"),
        (TELEGRAM_CHAT_ID, "CHAT_ID")
    ):
        if value == placeholder:
            raise RuntimeError(f"Заполни {placeholder}")

    state = load_state()
    bot = Bot(token=TELEGRAM_BOT_TOKEN)

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=VERIFY_TLS)
    ) as session:

        log.info("==============================")
        log.info("Gophish monitor started")
        log.info("Gophish: %s", GOPHISH_URL)
        log.info("Interval: %s sec", CHECK_INTERVAL)
        log.info("==============================")

        while True:
            try:
                await process_campaigns(session, bot, state)

            except asyncio.CancelledError:
                raise

            except Exception:
                log.exception("Ошибка при проверке Gophish")

            await asyncio.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        log.info("Gophish monitor stopped")