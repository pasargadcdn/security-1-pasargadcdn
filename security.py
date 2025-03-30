from flask import Flask, request, jsonify
import time
from collections import defaultdict
import re

app = Flask(__name__)

request_log = defaultdict(list)
blacklist = set()
RATE_LIMIT = 10
BLOCK_TIME = 300

bot_patterns = [
    re.compile(r"bot", re.IGNORECASE),
    re.compile(r"crawler", re.IGNORECASE),
    re.compile(r"spider", re.IGNORECASE),
]

@app.before_request
def block_attackers():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    current_time = time.time()
    
    if ip in blacklist:
        return jsonify({"error": "Access denied"}), 403
    
    if any(pattern.search(user_agent) for pattern in bot_patterns):
        blacklist.add(ip)
        return jsonify({"error": "Bot access denied"}), 403
    
    request_log[ip] = [t for t in request_log[ip] if current_time - t < 10]
    request_log[ip].append(current_time)
    
    if len(request_log[ip]) > RATE_LIMIT:
        blacklist.add(ip)
        return jsonify({"error": "Too many requests. You are temporarily blocked."}), 429

@app.route('/')
def home():
    return "Welcome to Secure Server!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)