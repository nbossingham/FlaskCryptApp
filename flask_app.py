from flask import Flask, request, render_template, make_response
from flask_socketio import SocketIO, send
import crypto
app = Flask(__name__)
socketio = SocketIO(app)
app.static_folder = 'static'

@socketio.on('message')
def encrypt(msg):
    send(msg, broadcast=True)

@app.route('/')
def home():
    userPrivate,userPublicX,userPublicY,userSharedX,userSharedY,botPrivate,botPublicX,botPublicY,botSharedX,botSharedY = diffieHellmanECC()

    
    return render_template('test.html',userPrivate=userPrivate,userPublicX=userPublicX,userPublicY=userPublicY,userSharedX=userSharedX,userSharedY=userSharedY,botPrivate=botPrivate,botPublicX=botPublicX,botPublicY=botPublicY,botSharedX=botSharedX,botSharedY=botSharedY)


