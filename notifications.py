"""
notifications.py — sends alerts via whichever channel(s) are enabled in config.json.

Windows toast needs nothing beyond `pip install win11toast` — it's on by default.
Telegram needs a bot token + chat id (see README "Notifications" section for the
2-minute setup with @BotFather) but reaches your phone, which a toast on this PC won't
if you're not sitting in front of it.

Both are best-effort: a failure to send (Telegram unreachable, toast API hiccup) is
logged and swallowed, never raised — a notification failing should not take down
notifier.py or block the thing that triggered it.
"""

import requests

import config


def send_windows_toast(title: str, message: str):
    try:
        from win11toast import toast
        toast(title, message)
        return True
    except Exception as e:
        print(f"[!] Windows toast failed: {e}")
        return False


def send_telegram(token: str, chat_id: str, title: str, message: str):
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": f"{title}\n{message}"},
            timeout=10,
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        print(f"[!] Telegram notification failed: {e}")
        return False


def notify(title: str, message: str):
    """Sends through every channel enabled in config.json. Safe to call even if nothing
    is configured — it just becomes a no-op."""
    cfg = config.load()
    sent_any = False

    if cfg.get("notify_windows_toast"):
        sent_any = send_windows_toast(title, message) or sent_any

    if cfg.get("notify_telegram") and cfg.get("telegram_bot_token") and cfg.get("telegram_chat_id"):
        sent_any = send_telegram(cfg["telegram_bot_token"], cfg["telegram_chat_id"], title, message) or sent_any

    if not sent_any:
        print(f"[i] (no notification channel configured/succeeded) {title}: {message}")

    return sent_any
