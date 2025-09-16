import os
import re
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timezone, timedelta
import requests

def getenv_bool(name, default=False):
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in ("1","true","yes","y","on")

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
    # allow_list admite emails completos o dominios (ej: @empresa.com)
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
    # Enlace de búsqueda por Message-ID en Gmail
    if not msgid:
        return None
    # Asegura que msgid vaya sin los <>
    mid = msgid.strip().lstrip("<").rstrip(">")
    return f"https://mail.google.com/mail/u/0/#search/rfc822msgid:{mid}"

def send_telegram(token, chat_id, text, disable_preview=True):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": disable_preview
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
    # Añadir etiqueta de Gmail mediante X-GM-LABELS (no marca como leído)
    try:
        typ, _ = M.uid("STORE", uid, "+X-GM-LABELS", f"({label})")
        return typ == "OK"
    except:
        return False

def add_notified_flag_imap(M, uid, keyword="Notified"):
    # Intento estándar IMAP: palabra clave (puede no estar soportada)
    try:
        typ, _ = M.uid("STORE", uid, "+FLAGS", f"({keyword})")
        if typ == "OK":
            return True
    except:
        pass
    # Fallback: usa \Flagged
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

    # Filtros
    senders = [s for s in os.getenv("SENDER_FILTERS", "").split(",") if s.strip()]
    if not senders:
        raise RuntimeError("Debes definir SENDER_FILTERS con emails o dominios")

    subj_keywords = [s for s in os.getenv("SUBJECT_KEYWORDS", "").split(",") if s.strip()]
    folder = os.getenv("IMAP_FOLDER", "INBOX")
    gmail_mode = getenv_bool("GMAIL_MODE", True)  # True si usas Gmail
    mark_as_read = getenv_bool("MARK_AS_READ", False)
    gmail_label_mode = getenv_bool("GMAIL_LABEL", True)  # poner etiqueta en Gmail
    recent_minutes = int(os.getenv("RECENT_MINUTES", "60"))  # para IMAP genérico limitar antigüedad

    M = imap_connect()
    try:
        # Necesitamos acceso de escritura si vamos a etiquetar/poner flags
        M.select(folder, readonly=not (gmail_label_mode or mark_as_read or True))

        uids_to_process = set()

        if gmail_mode:
            # Un único query X-GM-RAW con varios from y sin label:Notified
            # Además, limitamos a correos recientes para evitar históricos
            # newer_than admite m (min), h (hora), d (día). Usamos recent_minutes.
            or_clause = " OR ".join([f'"{s.strip()}"' for s in senders])
            gm_query = f'from:({or_clause}) -label:Notified newer_than:{max(5, min(recent_minutes, 1440))}m'
            typ, data = M.uid("SEARCH", "X-GM-RAW", gm_query)
            if typ == "OK" and data and data[0]:
                uids_to_process.update(data[0].decode().split())
        else:
            # IMAP genérico: buscamos FROM por cada remitente y luego filtramos por fecha/flags
            since_date = (datetime.now(timezone.utc) - timedelta(minutes=recent_minutes)).date()
            since_str = since_date.strftime("%d-%b-%Y")
            for s in senders:
                # Traemos incluso vistos; filtraremos por flags/fecha después
                typ, data = M.uid("SEARCH", None, '(FROM "{}" SINCE {})'.format(s.strip(), since_str))
                if typ == "OK" and data and data[0]:
                    for uid in data[0].decode().split():
                        uids_to_process.add(uid)

        for uid in sorted(uids_to_process):
            # Recuperamos headers + FLAGS + INTERNALDATE
            typ, data = M.uid("FETCH", uid, "(FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
            if typ != "OK" or not data:
                continue

            flags = b""
            headers_raw = b""
            internaldate = None

            for part in data:
                if not isinstance(part, tuple):
                    continue
                meta, payload = part
                meta_str = meta.decode(errors="ignore") if isinstance(meta, bytes) else str(meta)
                if "FLAGS" in meta_str:
                    flags = meta
                if "INTERNALDATE" in meta_str:
                    # imaplib ya parsea; aquí solo usamos payload si viene. Si no, confiar en Date header más abajo.
                    pass
                headers_raw = payload or headers_raw

            # Evitamos duplicados si ya fue "Notified" / \Flagged
            if already_notified_flags(flags):
                continue

            msg = email.message_from_bytes(headers_raw)
            from_hdr = decode_mime_words(msg.get("From"))
            subject = decode_mime_words(msg.get("Subject"))
            date_hdr = msg.get("Date")
            message_id = (msg.get("Message-ID") or "").strip()

            name, addr = normalize_addr(from_hdr)

            # Validamos remitente y asunto
            if not match_sender(addr, senders):
                continue
            if not subject_matches(subject, subj_keywords):
                continue

            # Filtrado por fecha reciente para genérico (si cabía algo antiguo)
            if date_hdr:
                try:
                    dt = parsedate_to_datetime(date_hdr)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                except:
                    dt = None
            else:
                dt = None

            if dt is None:
                # fallback: no date => dejamos pasar pero es raro
                dt_ok = True
            else:
                dt_ok = (datetime.now(timezone.utc) - dt) <= timedelta(days=2)

            if not dt_ok:
                continue

            # Construimos texto Telegram
            gmail_link = build_gmail_link_from_msgid(message_id) if gmail_mode else None
            when_str = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if dt else "desconocida"

            safe_from = f"{name} <{addr}>" if name else addr
            text = (
                "📧 <b>Nuevo correo importante</b>\n"
                f"👤 De: <b>{safe_from}</b>\n"
                f"📝 Asunto: <b>{(subject or '(sin asunto)').strip()}</b>\n"
                f"🗓️ Fecha: {when_str}\n"
            )
            if gmail_link:
                text += f'🔗 <a href="{gmail_link}">Abrir en Gmail</a>\n'

            # Enviar Telegram
            try:
                send_telegram(TELEGRAM_TOKEN, TELEGRAM_CHAT, text)
            except Exception as e:
                print(f"[WARN] Error al enviar Telegram: {e}")
                continue

            # Marcar como notificado
            stored = False
            if gmail_mode and getenv_bool("GMAIL_LABEL", True):
                stored = add_notified_marker_gmail(M, uid, os.getenv("GMAIL_LABEL_NAME", "Notified"))

            if not stored:
                if getenv_bool("ADD_IMAP_KEYWORD", True):
                    stored = add_notified_flag_imap(M, uid, os.getenv("IMAP_KEYWORD_NAME", "Notified"))

            # Opcional: marcar como leído si así se pide
            if not stored and getenv_bool("MARK_AS_READ", False):
                try:
                    M.uid("STORE", uid, "+FLAGS", r"(\Seen)")
                except Exception as e:
                    print(f"[WARN] No se pudo marcar como leído: {e}")

        M.logout()
    except Exception as e:
        print(f"[ERROR] {e}")
        try:
            M.logout()
        except:
            pass

if __name__ == "__main__":
    main()
