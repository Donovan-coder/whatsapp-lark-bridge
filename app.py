import os
import re
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Load config from environment variables ──────────────────────────────────
VERIFY_TOKEN         = os.environ["VERIFY_TOKEN"]
WHATSAPP_TOKEN       = os.environ["WHATSAPP_TOKEN"]
WHATSAPP_PHONE_ID    = os.environ["WHATSAPP_PHONE_ID"]
WHATSAPP_APP_SECRET  = os.environ["WHATSAPP_APP_SECRET"]

LARK_APP_ID          = os.environ["LARK_APP_ID"]
LARK_APP_SECRET      = os.environ["LARK_APP_SECRET"]
LARK_CHAT_ID         = os.environ["LARK_CHAT_ID"]

# In-memory store mapping Lark message thread → WhatsApp number
thread_to_wa: dict[str, str] = {}
wa_to_thread: dict[str, str] = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_lark_token() -> str:
    """Get a short-lived Lark tenant access token."""
    resp = requests.post(
        "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal",
        json={"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["tenant_access_token"]


def send_to_lark(wa_number: str, message: str) -> str:
    """
    Post an incoming WhatsApp message to the Lark group chat.
    Returns the message_id of the posted message (used to thread replies).
    """
    token = get_lark_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    root_id = wa_to_thread.get(wa_number)
    payload = {
        "receive_id": LARK_CHAT_ID,
        "msg_type": "text",
        "content": f'{{"text": "📱 WhatsApp [{wa_number}]:\\n{message}"}}',
    }
    if root_id:
        payload["root_id"] = root_id

    resp = requests.post(
        "https://open.larksuite.com/open-apis/im/v1/messages?receive_id_type=chat_id",
        headers=headers,
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    msg_id = data["data"]["message_id"]

    # First message from this number — store the root thread
    if not root_id:
        wa_to_thread[wa_number] = msg_id
        thread_to_wa[msg_id] = wa_number

    return msg_id


def send_to_whatsapp(wa_number: str, message: str):
    """Send a text message to a WhatsApp number via Meta Cloud API."""
    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": wa_number,
        "type": "text",
        "text": {"body": message},
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    resp.raise_for_status()


def verify_whatsapp_signature(request) -> bool:
    """Validate that the webhook request genuinely came from Meta."""
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(
        WHATSAPP_APP_SECRET.encode(), request.data, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def strip_mentions(text: str) -> str:
    """Remove @mentions like @WhatsApp Bridge from text."""
    # Remove @mentions (e.g. @SomeName)
    cleaned = re.sub(r'@\S+(?:\s+\S+)*?(?=\s|$)', '', text)
    # Also remove any remaining @ symbols with following words
    cleaned = re.sub(r'@[^\s]*', '', cleaned)
    return cleaned.strip()


# ── WhatsApp webhook ──────────────────────────────────────────────────────────

@app.route("/webhook/whatsapp", methods=["GET", "POST"])
def whatsapp_webhook():
    if request.method == "GET":
        if request.args.get("hub.verify_token") == VERIFY_TOKEN:
            return request.args.get("hub.challenge", ""), 200
        return "Forbidden", 403

    if not verify_whatsapp_signature(request):
        return "Unauthorized", 401

    data = request.json
    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for msg in value.get("messages", []):
                    if msg.get("type") == "text":
                        wa_number = msg["from"]
                        text      = msg["text"]["body"]
                        send_to_lark(wa_number, text)
    except Exception as e:
        app.logger.error(f"WhatsApp webhook error: {e}")

    return jsonify({"status": "ok"}), 200


# ── Lark webhook ──────────────────────────────────────────────────────────────

@app.route("/webhook/lark", methods=["POST"])
def lark_webhook():
    data = request.json

    # Lark URL verification
    if data.get("type") == "url_verification":
        return jsonify({"challenge": data["challenge"]})

    try:
        event = data.get("event", {})
        msg   = event.get("message", {})

        # Ignore messages sent by the bot itself
        sender_type = event.get("sender", {}).get("sender_type", "")
        if sender_type == "app":
            return jsonify({"status": "ignored"}), 200

        msg_type = msg.get("message_type")
        if msg_type != "text":
            return jsonify({"status": "ignored"}), 200

        import json as _json
        raw_text = _json.loads(msg.get("content", "{}")).get("text", "").strip()
        
        # Strip @mentions from the reply
        text = strip_mentions(raw_text)
        
        if not text:
            return jsonify({"status": "empty_after_strip"}), 200

        # Check root_id first, then parent_id, then message_id
        root_id   = msg.get("root_id")
        parent_id = msg.get("parent_id")
        msg_id    = msg.get("message_id")

        app.logger.info(f"Lark reply: root_id={root_id}, parent_id={parent_id}, msg_id={msg_id}")
        app.logger.info(f"thread_to_wa keys: {list(thread_to_wa.keys())}")

        # Try to find the WhatsApp number from any of the IDs
        wa_number = (
            thread_to_wa.get(root_id) or
            thread_to_wa.get(parent_id) or
            thread_to_wa.get(msg_id)
        )

        if not wa_number:
            app.logger.warning(f"No WhatsApp thread found for root_id={root_id}")
            return jsonify({"status": "no_thread"}), 200

        app.logger.info(f"Sending to WhatsApp {wa_number}: {text}")
        send_to_whatsapp(wa_number, text)

    except Exception as e:
        app.logger.error(f"Lark webhook error: {e}")

    return jsonify({"status": "ok"}), 200


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
