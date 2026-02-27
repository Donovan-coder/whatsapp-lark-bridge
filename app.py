import os
import re
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VERIFY_TOKEN         = os.environ["VERIFY_TOKEN"]
WHATSAPP_TOKEN       = os.environ["WHATSAPP_TOKEN"]
WHATSAPP_PHONE_ID    = os.environ["WHATSAPP_PHONE_ID"]
WHATSAPP_APP_SECRET  = os.environ["WHATSAPP_APP_SECRET"]
LARK_APP_ID          = os.environ["LARK_APP_ID"]
LARK_APP_SECRET      = os.environ["LARK_APP_SECRET"]
LARK_CHAT_ID         = os.environ["LARK_CHAT_ID"]

thread_to_wa: dict[str, str] = {}
wa_to_thread: dict[str, str] = {}


def get_lark_token() -> str:
    resp = requests.post(
        "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal",
        json={"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["tenant_access_token"]


def send_to_lark(wa_number: str, message: str) -> str:
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

    app.logger.info(f"Posted to Lark, message_id={msg_id}")

    if not root_id:
        wa_to_thread[wa_number] = msg_id
        thread_to_wa[msg_id] = wa_number
        # Store with om_ prefix variant too
        if msg_id.startswith("om_"):
            pass  # already stored
        else:
            om_id = "om_" + msg_id
            thread_to_wa[om_id] = wa_number
        app.logger.info(f"Stored thread mapping: {msg_id} -> {wa_number}")
        app.logger.info(f"All thread keys: {list(thread_to_wa.keys())}")

    return msg_id


def send_to_whatsapp(wa_number: str, message: str):
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
    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(
        WHATSAPP_APP_SECRET.encode(), request.data, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def strip_mentions(text: str) -> str:
    cleaned = re.sub(r'@[^\s]+(?:\s+[^\s@]+)*', '', text)
    return cleaned.strip()


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


@app.route("/webhook/lark", methods=["POST"])
def lark_webhook():
    data = request.json

    if data.get("type") == "url_verification":
        return jsonify({"challenge": data["challenge"]})

    try:
        event = data.get("event", {})
        msg   = event.get("message", {})

        sender_type = event.get("sender", {}).get("sender_type", "")
        if sender_type == "app":
            return jsonify({"status": "ignored"}), 200

        msg_type = msg.get("message_type")
        if msg_type != "text":
            return jsonify({"status": "ignored"}), 200

        import json as _json
        raw_text = _json.loads(msg.get("content", "{}")).get("text", "").strip()
        text = strip_mentions(raw_text)

        if not text:
            return jsonify({"status": "empty_after_strip"}), 200

        root_id   = msg.get("root_id")
        parent_id = msg.get("parent_id")
        msg_id    = msg.get("message_id")

        app.logger.info(f"Lark reply: root_id={root_id}, parent_id={parent_id}, msg_id={msg_id}")
        app.logger.info(f"Known threads: {list(thread_to_wa.keys())}")

        wa_number = (
            thread_to_wa.get(root_id) or
            thread_to_wa.get(parent_id) or
            thread_to_wa.get(msg_id)
        )

        if not wa_number:
            app.logger.warning(f"No thread found. root_id={root_id}, known={list(thread_to_wa.keys())}")
            return jsonify({"status": "no_thread"}), 200

        app.logger.info(f"Sending to WhatsApp {wa_number}: {text}")
        send_to_whatsapp(wa_number, text)

    except Exception as e:
        app.logger.error(f"Lark webhook error: {e}")

    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
