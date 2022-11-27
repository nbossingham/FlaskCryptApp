from flask import Flask, request, render_template, make_response
from flask_socketio import SocketIO, send

app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('message')
def encrypt(msg):
    send(msg, broadcast=True)

@app.route('/')
def home():
    return render_template('test.html')


