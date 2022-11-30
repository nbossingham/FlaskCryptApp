from flask import Flask, request, render_template, make_response
from flask_socketio import SocketIO, send
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import random
import hashlib
## CURVE: 
##     y^2 = x^3 +2x + 2 mod 17
## BASE POINT:
##     (5,1)
## ORDER:
##      19

a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
mod = 115792089210356248762697446949407573530086143415290314195533631308867097853951
order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
x0 = 48439561293906451759052585252797914202762949526041747995844080717082404635286
y0 = 36134250956749795798585127919587881956611106672985015071877198253568414405109

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
	

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = bytes.fromhex("A30D2848066868576B62A8E7DF2EBF48")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8"),iv,plain_text

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = bytes.fromhex("A30D2848066868576B62A8E7DF2EBF48")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]
	
##START QUOTED CODE
##This code is the very baseline of ECC. These methods are all required 
##to enact ECC. This code was borrowed from serengil 
##@https://github.com/serengil/crypto/blob/master/python/EccCore.py

def findModularInverse(a, mod):
			
	while(a <= 0):
		a = a + mod
	
	#a = a % mod
	
	x1 = 1; x2 = 0; x3 = mod
	y1 = 0; y2 = 1; y3 = a
	
	q = int((x3/y3))
	t1 = x1 - q*y1
	t2 = x2 - q*y2
	t3 = x3 - (q*y3)
	
	
	while(y3 != 1):
		x1 = y1; x2 = y2; x3 = y3
		
		y1 = t1; y2 = t2; y3 = t3
		
		q = int(x3 / y3)
		t1 = x1 - q*y1
		t2 = x2 - q*y2
		t3 = x3 - (q*y3)
		
		
	while(y2 < 0):
		y2 = y2 + mod
	
	return y2

def pointAddition(x1, y1, x2, y2, a, b, mod):
	#print(f"x1:{x1},y1:{y1}")
	#print(f"x2:{x2},y2:{y2}")
	skip = False
	if x1 == x2 and y1 == y2:
		#doubling
		beta = (3*x1*x1 + a) * (findModularInverse(2*y1, mod))
	else:
		#point addition
		#print(f"x1:{x1},y1:{y1}")
		beta = (y2 - y1)*(findModularInverse((x2 - x1), mod))
	if skip==False:
	    x3 = beta*beta - x1 - x2
	    y3 = beta*(x1 - x3) - y1
	
	x3 = x3 % mod
	y3 = y3 % mod
	
	while(x3 < 0):
		x3 = x3 + mod
	
	while(y3 < 0):
		y3 = y3 + mod
	#print(f"x3:{x3},y3:{y3}")
	return x3, y3

def applyDoubleAndAddMethod(x0, y0, k, a, b, mod):
	
	x_temp = x0
	y_temp = y0
	
	kAsBinary = bin(int(k))#0b1111111001
	kAsBinary = kAsBinary[2:] #1111111001
	#print(f"Numerical Key: {int(k,16)}")
	#print(f"Binary Key: {kAsBinary}")
	
	for i in range(1, len(kAsBinary)):
		currentBit = kAsBinary[i: i+1]
		#print(f"{i}:")
		#always apply doubling
		
		x_temp, y_temp = pointAddition(x_temp, y_temp, x_temp, y_temp, a, b, mod)
		
		if currentBit == '1':
			#add base point
			x_temp, y_temp = pointAddition(x_temp, y_temp, x0, y0, a, b, mod)
		#print(f"xt:{x_temp},yt:{y_temp}")
	return x_temp, y_temp

## END QUOTED CODE

## ECDH with 128 bit keys

def diffieHellmanECC():
    #os.urandom(16).hex()
    userPrivate = random.randrange(pow(2,255),order-1)
    
    userPublicX,userPublicY = applyDoubleAndAddMethod(x0, y0, userPrivate, a, b, mod)
    ##print(f"Private Key: {userPrivate}")
    ##print(f"Numerical Key: {int(userPrivate)}")
    ##print(f"pubx: {userPublicX},puby {userPublicY}")
    
    botPrivate = random.randrange(pow(2,255),order-1)
    
    botPublicX,botPublicY = applyDoubleAndAddMethod(x0, y0, botPrivate, a, b, mod)
    ##print(f"Private Key: {botPrivate}")
    ##print(f"Numerical Key: {int(botPrivate)}")
    ##print(f"pubx: {botPublicX},puby {botPublicY}")
    
    userSharedX, userSharedY = applyDoubleAndAddMethod(botPublicX, botPublicY, userPrivate, a, b, mod)
    print(f"pubx: {userSharedX},puby {userSharedY}")
    
    botSharedX, botSharedY = applyDoubleAndAddMethod(userPublicX, userPublicY, botPrivate, a, b, mod)
    print(f"pubx: {botSharedX},puby {botSharedY}")
    
    return userPrivate,userPublicX,userPublicY,userSharedX,userSharedY,botPrivate,botPublicX,botPublicY,botSharedX,botSharedY


	

userPrivate,userPublicX,userPublicY,userSharedX,userSharedY,botPrivate,botPublicX,botPublicY,botSharedX,botSharedY = diffieHellmanECC()
	
userPrintData=f"<b>Private Key:</b> 0x{userPrivate:X}<br> <b>Public X:</b> 0x{userPublicX:X}<br> <b>Public Y:</b> 0x{userPublicY:X}"
botPrintData=f"<b>Private Key:</b> 0x{botPrivate:X}<br> <b>Public X:</b> 0x{botPublicX:X}<br> <b>Public Y:</b> 0x{botPublicY:X}"
userSharedKey=f" <b>Shared X:</b> 0x{userSharedX:X}<br> <b>Public Y:</b> 0x{userSharedY:X}"
botSharedKey=f" <b>Shared X:</b>  0x{botSharedX:X}<br> <b>Public Y:</b> 0x{botSharedY:X}"
currentMsg=""
def aesEncrypt(msg,sharedKey): #Going to use AES with CBC
  print(f"Mesage:{msg}")
  aes = AESCipher(key="0x{userSharedX:X}")
  print("Initialized")
  encrMsg = aes.encrypt(msg)
  print(f"Encr Mesage:{encrMsg}")
  decrMsg = aes.decrypt(encrMsg)
  return encrMsg,decrMsg
	
	
def aesDecrypt(encrMsg,SharedKey):
	print(f"Encr Mesage:{encrMsg}")
	aes = AESCipher(key="0x{userSharedX:X}")
	decrMsg = aes.decrypt(msg)
	print(f"Mesage:{decrMsg}")
	return decrMsg


app = Flask(__name__)
socketio = SocketIO(app)
app.static_folder = 'static'


    
@app.route('/')
def home():
	
    userPrintData=f"<b>Private Key:</b> 0x{userPrivate:X}<br> <b>Public X:</b> 0x{userPublicX:X}<br> <b>Public Y:</b> 0x{userPublicY:X}"
    botPrintData=f"<b>Private Key:</b> 0x{botPrivate:X}<br> <b>Public X:</b> 0x{botPublicX:X}<br> <b>Public Y:</b> 0x{botPublicY:X}"
    userSharedKey=f" <b>Shared X:</b> 0x{userSharedX:X}<br> <b>Public Y:</b> 0x{userSharedY:X}"
    botSharedKey=f" <b>Shared X:</b>  0x{botSharedX:X}<br> <b>Public Y:</b> 0x{botSharedY:X}"
    return render_template('test.html',dhDataUser=userPrintData,dhDataBot=botPrintData,shrDataUser=userSharedKey,shrDataBot=botSharedKey)

def messageSent(msg):
    userPrintData=f"<b>Private Key:</b> 0x{userPrivate:X}<br> <b>Public X:</b> 0x{userPublicX:X}<br> <b>Public Y:</b> 0x{userPublicY:X}"
    botPrintData=f"<b>Private Key:</b> 0x{botPrivate:X}<br> <b>Public X:</b> 0x{botPublicX:X}<br> <b>Public Y:</b> 0x{botPublicY:X}"
    userSharedKey=f" <b>Shared X:</b> 0x{userSharedX:X}<br> <b>Public Y:</b> 0x{userSharedY:X}"
    botSharedKey=f" <b>Shared X:</b>  0x{botSharedX:X}<br> <b>Public Y:</b> 0x{botSharedY:X}"
    user = AESCipher(key="0x{userSharedX:X}")
	bot = AESCipher(key="0x{botSharedX:X}")
	encrMsg,userIV,paddedText= user.encrypt(msg)
	decrMsg = bot.decrypt(encrMsg)
    socketio.emit('messageEncryptionEvent',[encrMsg,decrMsg,userSharedKey,botSharedKey],broadcast=True)

@socketio.on('message')
def encrypt(msg):
    send(msg, broadcast=True)
    print(msg)
    messageSent(msg)
    
