from flask import Flask, request, render_template, make_response
from flask_socketio import SocketIO, send

app = Flask(__name__)
socketio = socketIO(app)

@socketio.on('message')
def encrypt(msg):
    send(msg, broadcast=True)


if __name__=='__main__':
   socketio.run(app)

