import os
import re
import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VERIFY_TOKEN         = os.environ["VERIFY_TOKEN"]
WHATSAPP_TOKEN       = os.environ["WHATSAPP_TOKEN"]
WHATSAPP_PHONE_ID    = os.environ["WHATSAPP_PHONE_ID"]
LARK_APP_ID          = os.environ["LARK_APP_ID"]
LARK_APP_SECRET      = os.environ["LARK_APP_SECRET"]
LARK_CHAT_ID         = os.environ["LARK_CHAT_ID"]

thread_to_wa = {}
wa_to_thread = {}


def get_lark_token():
    resp = requests.post(
        "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal",
        json={"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["tenant_access_token"]


def send_to_lark(wa_number, message):
    token = get_lark_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    root_id = wa_to_thread.get(wa_number)
    payload = {
        "receive_id": LARK_CHAT_ID,
        "msg_type": "text",
        "content": json.dumps({"text": f"📱 WhatsApp [{wa_number}]:\n{message}"}),
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
    msg_id = resp.json()["data"]["message_id"]
    print(f"SENT TO LARK: msg_id={msg_id} for wa={wa_number}", flush=True)

    if not root_id:
        wa_to_thread[wa_number] = msg_id
        thread_to_wa[msg_id] = wa_number
        print(f"STORED: {msg_id} -> {wa_number}", flush=True)
        print(f"ALL THREADS: {thread_to_wa}", flush=True)

    return msg_id


def send_to_whatsapp(wa_number, message):
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
    print(f"WHATSAPP SEND STATUS: {resp.status_code} {resp.text}", flush=True)
    resp.raise_for_status()


def strip_mentions(text):
    return re.sub(r'@\S+', '', text).strip()


@app.route("/webhook/whatsapp", methods=["GET", "POST"])
def whatsapp_webhook():
    if request.method == "GET":
        if request.args.get("hub.verify_token") == VERIFY_TOKEN:
            return request.args.get("hub.challenge", ""), 200
        return "Forbidden", 403

    data = request.json
    print(f"WA WEBHOOK: {json.dumps(data)[:500]}", flush=True)
    try:
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for msg in value.get("messages", []):
                    if msg.get("type") == "text":
                        wa_number = msg["from"]
                        text = msg["text"]["body"]
                        print(f"WA MESSAGE from {wa_number}: {text}", flush=True)
                        send_to_lark(wa_number, text)
    except Exception as e:
        print(f"WA ERROR: {e}", flush=True)

    return jsonify({"status": "ok"}), 200


@app.route("/webhook/lark", methods=["POST"])
def lark_webhook():
    data = request.json
    print(f"LARK WEBHOOK: {json.dumps(data)[:500]}", flush=True)

    if data.get("type") == "url_verification":
        return jsonify({"challenge": data["challenge"]})

    try:
        event = data.get("event", {})
        msg = event.get("message", {})

        sender_type = event.get("sender", {}).get("sender_type", "")
        if sender_type == "app":
            return jsonify({"status": "ignored"}), 200

        if msg.get("message_type") != "text":
            return jsonify({"status": "ignored"}), 200

        raw_text = json.loads(msg.get("content", "{}")).get("text", "").strip()
        text = strip_mentions(raw_text)
        print(f"LARK REPLY text='{text}'", flush=True)

        if not text:
            return jsonify({"status": "empty"}), 200

        root_id = msg.get("root_id")
        parent_id = msg.get("parent_id")
        msg_id = msg.get("message_id")

        print(f"LARK IDs: root={root_id} parent={parent_id} msg={msg_id}", flush=True)
        print(f"KNOWN THREADS: {thread_to_wa}", flush=True)

        wa_number = (
            thread_to_wa.get(root_id) or
            thread_to_wa.get(parent_id) or
            thread_to_wa.get(msg_id)
        )

        if not wa_number:
            print(f"NO THREAD FOUND for root={root_id}", flush=True)
            return jsonify({"status": "no_thread"}), 200

        print(f"SENDING TO WA {wa_number}: {text}", flush=True)
        send_to_whatsapp(wa_number, text)

    except Exception as e:
        print(f"LARK ERROR: {e}", flush=True)

    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
