import os
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timezone, timedelta
import requests

DEBUG = True  # 👈 activa el modo debug

def log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

def getenv_bool(name, default=False):
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "y", "on")

def decode_mime_words(s):
    if not s:
        return ""
    parts = decode_header(s)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            try:
                out.append(text.decode(enc or "utf-8", errors="replace"))
            except:
                out.append(text.decode("utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)

def normalize_addr(addr):
    name, email_addr = parseaddr(addr)
    return (name.strip(), email_addr.strip().lower())

def match_sender(sender_addr, allow_list):
    sender = sender_addr.lower()
    for item in allow_list:
        it = item.strip().lower()
        if not it:
            continue
        if it.startswith("@"):
            if sender.endswith(it):
                return True
        elif sender == it:
            return True
    return False

def subject_matches(subject, keywords):
    if not keywords:
        return True
    subj = (subject or "").lower()
    for kw in keywords:
        kw = kw.strip().lower()
        if kw and kw in subj:
            return True
    return False

def build_gmail_link_from_msgid(msgid):
    if not msgid:
        return None
    mid = msgid.strip().lstrip("<").rstrip(">")
    return f"https://mail.google.com/mail/u/0/#search/rfc822msgid:{mid}"

def send_telegram(token, chat_id, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()

def imap_connect():
    host = os.getenv("IMAP_HOST")
    port = int(os.getenv("IMAP_PORT", "993"))
    user = os.getenv("IMAP_USER")
    pwd  = os.getenv("IMAP_PASS")

    if not host or not user or not pwd:
        raise RuntimeError("Faltan IMAP_HOST / IMAP_USER / IMAP_PASS")

    use_ssl = getenv_bool("IMAP_SSL", True)
    if use_ssl:
        M = imaplib.IMAP4_SSL(host, port)
    else:
        M = imaplib.IMAP4(host, port)
        if getenv_bool("IMAP_STARTTLS", False):
            M.starttls()
    M.login(user, pwd)
    return M

def add_notified_marker_gmail(M, uid, label="Notified"):
    try:
        typ, _ = M.uid("STORE", uid, "+X-GM-LABELS", f"({label})")
        return typ == "OK"
    except:
        return False

def add_notified_flag_imap(M, uid, keyword="Notified"):
    try:
        typ, _ = M.uid("STORE", uid, "+FLAGS", f"({keyword})")
        if typ == "OK":
            return True
    except:
        pass
    try:
        typ, _ = M.uid("STORE", uid, "+FLAGS", r"(\Flagged)")
        return typ == "OK"
    except:
        return False

def already_notified_flags(flags_bytes):
    flags = flags_bytes.decode(errors="ignore") if isinstance(flags_bytes, bytes) else str(flags_bytes or "")
    return ("Notified" in flags) or (r"\Flagged" in flags)

def main():
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT  = os.getenv("TELEGRAM_CHAT_ID")
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        raise RuntimeError("Faltan TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID")

    senders = [s for s in os.getenv("SENDER_FILTERS", "").split(",") if s.strip()]
    if not senders:
        raise RuntimeError("Debes definir SENDER_FILTERS con emails o dominios")

    subj_keywords = [s for s in os.getenv("SUBJECT_KEYWORDS", "").split(",") if s.strip()]
    folder = os.getenv("IMAP_FOLDER", "INBOX")
    gmail_mode = getenv_bool("GMAIL_MODE", True)
    mark_as_read = getenv_bool("MARK_AS_READ", False)
    gmail_label_mode = getenv_bool("GMAIL_LABEL", True)
    recent_minutes = int(os.getenv("RECENT_MINUTES", "60"))

    M = imap_connect()
    try:
        M.select(folder, readonly=False)

        uids_to_process = set()

        if gmail_mode:
            or_clause = " OR ".join([f'"{s.strip()}"' for s in senders])
            gm_query = f'from:({or_clause}) -label:Notified newer_than:{max(5, min(recent_minutes, 1440))}m'
            log(f"Gmail search query: {gm_query}")
            typ, data = M.uid("SEARCH", None, "X-GM-RAW", gm_query)
            log(f"SEARCH result typ={typ}, data={data}")
            if typ == "OK" and data and data[0]:
                uids_to_process.update(data[0].decode().split())
        else:
            since_date = (datetime.now(timezone.utc) - timedelta(minutes=recent_minutes)).date()
            since_str = since_date.strftime("%d-%b-%Y")
            for s in senders:
                typ, data = M.uid("SEARCH", None, f'(FROM "{s.strip()}" SINCE {since_str})')
                log(f"SEARCH {s}: typ={typ}, data={data}")
                if typ == "OK" and data and data[0]:
                    for uid in data[0].decode().split():
                        uids_to_process.add(uid)

        for uid in sorted(uids_to_process):
            typ, data = M.uid("FETCH", uid, "(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
            if typ != "OK" or not data:
                continue

            headers_raw = b""
            for part in data:
                if not isinstance(part, tuple):
                    continue
                _, payload = part
                headers_raw = payload or headers_raw

            msg = email.message_from_bytes(headers_raw)
            from_hdr = decode_mime_words(msg.get("From"))
            subject = decode_mime_words(msg.get("Subject"))
            log(f"Found UID {uid}: from={from_hdr}, subject={subject}")

        M.logout()
    except Exception as e:
        print(f"[ERROR] {e}")
        try:
            M.logout()
        except:
            pass

if __name__ == "__main__":
    main()
