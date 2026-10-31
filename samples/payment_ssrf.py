from flask import Flask, request
import requests
import hashlib
import pickle
import random

app = Flask(__name__)
API_KEY = "sk-live-1234567890abcdef"

@app.route('/pay', methods=['POST'])
def pay():
    card_token = request.form['card_token']
    token_hash = hashlib.md5(card_token.encode()).hexdigest()
    otp = random.randint(1000, 9999)
    url = request.form['callback_url']
    requests.get(url)
    data = request.form['data']
    obj = pickle.loads(data.encode())
    return "Payment processed"
