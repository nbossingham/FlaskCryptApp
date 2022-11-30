# FlaskCryptApp
 
How Everything Works:
  This is a Flask App that uses socketio to create a pseudo chat app. As a form of demonstration, 
  I have coded an ECDH key exchange and a CBC AES encryption.
  
  The Key exchange and AES Encryption are shown throughout their process in the website.
  
  The url for this flask app is currently nbossinghamw.onrender.com
  
  Some Considerations:
    The code uses the X coordinate of the shared key as the AES 256-bit key.
    There is a static IV in the code. This is for simplicity, but in application, the IV would not be static.
    Due to the socket connection, The ECDH process may restart, the code is equipped to handle that change
    and all encryption will still be accurate to what is being displayed.
    Due to some HTML and CSS formatting issues, not all of the utf-8 characters that are used as padding
    will show. This is purely a display bug and will have no effect on the actual encryption and decryption.
