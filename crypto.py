import os
## CURVE: 
##     y^2 = x^3 +2x + 2 mod 17
## BASE POINT:
##     (5,1)
## ORDER:
##      19

a = 2
b = 2
mod = 17
order = 19
x0 = 5
y0 = 1

##START QUOTED CODE
##This code is the very baseline of ECC. These methods are all required 
##to enact ECC. This code was borrowed from serengil 
##@https://github.com/serengil/crypto/blob/master/python/EccCore.py

def findModularInverse(a, mod):
			
	while(a < 0):
		a = a + mod
	
	#a = a % mod
	
	x1 = 1; x2 = 0; x3 = mod
	y1 = 0; y2 = 1; y3 = a
	
	q = int(x3 / y3)
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
	
	if x1 == x2 and y1 == y2:
		#doubling
		beta = (3*x1*x1 + a) * (findModularInverse(2*y1, mod))
	
	else:
		#point addition
		beta = (y2 - y1)*(findModularInverse((x2 - x1), mod))
	
	x3 = beta*beta - x1 - x2
	y3 = beta*(x1 - x3) - y1
	
	x3 = x3 % mod
	y3 = y3 % mod
	
	while(x3 < 0):
		x3 = x3 + mod
	
	while(y3 < 0):
		y3 = y3 + mod
	
	return x3, y3

def applyDoubleAndAddMethod(x0, y0, k, a, b, mod):
	
	x_temp = x0
	y_temp = y0
	
	kAsBinary = bin(k) #0b1111111001
	kAsBinary = kAsBinary[2:len(kAsBinary)] #1111111001
	#print(kAsBinary)
	
	for i in range(1, len(kAsBinary)):
		currentBit = kAsBinary[i: i+1]
		#always apply doubling
		x_temp, y_temp = pointAddition(x_temp, y_temp, x_temp, y_temp, a, b, mod)
		
		if currentBit == '1':
			#add base point
			x_temp, y_temp = pointAddition(x_temp, y_temp, x0, y0, a, b, mod)
	
	return x_temp, y_temp

## END QUOTED CODE

## ECDH with 128 bit keys

def diffieHellmanECC():
    userPrivate = os.urandom(16).hex()
    userPublicX,userPublicY = applyDoubleAndAddMethod(x0, y0, userPrivate, a, b, mod)

    botPrivate = os.urandom(16).hex()
    botPublicX,botPublicY = applyDoubleAndAddMethod(x0, y0, botPrivate, a, b, mod)
    
    userSharedX, userSharedY = applyDoubleAndAddMethod(botPublicX, botPublicY, userPrivate, a, b, mod)
    botSharedX, botSharedY = applyDoubleAndAddMethod(userPublicX, userPublicY, botPrivate, a, b, mod)
