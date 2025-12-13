import hashlib
import hmac
import json
import subprocess

from flask import Flask, jsonify, request

GITHUB_SECRET = "your_github_webhook_secret"

app = Flask(__name__)


def verify_signature(payload, signature):
    mac = hmac.new(GITHUB_SECRET.encode(), payload, hashlib.sha256)
    return hmac.compare_digest(f"sha256={mac.hexdigest()}", signature)


@app.route("/webhook", methods=["POST"])
def github_webhook():
    payload = request.get_data()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(payload, signature):
        return jsonify({"error": "Invalid signature"}), 403

    event = json.loads(payload)

    if event.get("action") in ["opened", "synchronize"]:
        pr_url = event["pull_request"]["html_url"]

        print(f"🔍 Scanning PR from {pr_url}...")
        subprocess.run(["python3", "src/policy_checker.py"], check=True)

    return jsonify({"message": "Webhook received"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
