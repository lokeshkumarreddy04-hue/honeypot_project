import json
import sqlite3
import time
import joblib
import requests
from datetime import datetime

# Telegram Config
TELEGRAM_BOT_TOKEN = "7815739380:AAHI0bZrkMVydMuu7sChgb6kPkmAGr0H7D4"
TELEGRAM_CHAT_ID = "1429153153"

# Load ML model & encoders
model = joblib.load("model/xgb_model.pkl")
vectorizer = joblib.load("model/vectorizer.pkl")
label_encoder = joblib.load("model/label_encoder.pkl")

# DB setup
conn = sqlite3.connect("alerts.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    ip TEXT,
    command TEXT,
    threat_level TEXT
)
""")
conn.commit()

# Alert function
def send_telegram_alert(ip, command, threat_level):
    msg = f"🚨 *Threat Detected!*\n\n*IP:* `{ip}`\n*Command:* `{command}`\n*Threat Level:* *{threat_level}*"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, data=payload)
    except Exception as e:
        print(f"[Telegram Error] {e}")

# Log monitor
def monitor_log(log_path):
    print(f"[~] Monitoring: {log_path}")
    with open(log_path, "r") as f:
        f.seek(0, 2)  # Go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                data = json.loads(line)
                if data.get("eventid") == "cowrie.command.input":
                    ip = data.get("src_ip")
                    cmd = data.get("input")
                    timestamp = data.get("timestamp")

                    # Vectorize command properly
                    cmd_clean = cmd.lower()
                    X = vectorizer.transform([cmd_clean])
                    prediction = model.predict(X)[0]
                    threat_level = label_encoder.inverse_transform([prediction])[0]

                    # Terminal
                    print(f"[{timestamp}] {ip} >> {cmd} => THREAT: {threat_level}")

                    # Telegram
                    send_telegram_alert(ip, cmd, threat_level)

                    # DB
                    cursor.execute("INSERT INTO alerts (timestamp, ip, command, threat_level) VALUES (?, ?, ?, ?)",
                                   (timestamp, ip, cmd, threat_level))
                    conn.commit()
            except Exception as e:
                print(f"⚠️ Error: {e}")

if __name__ == "__main__":
    monitor_log("/home/honeypot/cowrie-new/logs/cowrie.json")


