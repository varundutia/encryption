from flask import Flask, render_template, request,session,url_for,redirect
import sqlite3
from PIL import Image
import base64, re
import os
import chilkat
import shutil
import base64
app = Flask(__name__)
app.secret_key = 'encryption'
def convertToBinaryData(filename):
    with open(filename, 'rb') as file:
        blobData = file.read()
    return blobData
def writeTofile(data, filename):
    # Convert binary data to proper format and write it on Hard Disk
    with open(filename, 'wb') as file:
        file.write(data)
    print("Stored blob data into: ", filename, "\n")
def insertBLOB(name, key, photo,enc_type,text):
    try:
        conn = sqlite3.connect('registerDB.db')
        cur = conn.cursor()

        empPhoto = convertToBinaryData(photo)
        # Convert data into tuple format
        cur.execute('UPDATE REGISTER SET encrypted_img = ? , key = ?, enc_type=? ,encrypted_text=? where name = ?',(empPhoto,key,enc_type,text,name))
        conn.commit()
        print("Image and file inserted successfully as a BLOB into a table")
        cur.close()

    except sqlite3.Error as error:
        print("Failed to insert blob data into sqlite table", error)
    finally:
        if (conn):
            conn.close()
            print("the sqlite connection is closed")

# Convert encoding data into 8-bit binary
# form using ASCII value of characters
def genData(data):

        # list of binary codes
        # of given data
        newd = []

        for i in data:
            newd.append(format(ord(i), '08b'))
        return newd

# Pixels are modified according to the
# 8-bit binary data and finally returned
def modPix(pix, data):

    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):

        # Extracting 3 pixels at a time
        pix = [value for value in imdata.__next__()[:3] +
                                imdata.__next__()[:3] +
                                imdata.__next__()[:3]]

        # Pixel value should be made
        # odd for 1 and even for 0
        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j]% 2 != 0):
                pix[j] -= 1

            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if(pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1
                # pix[j] -= 1

        # Eighth pixel of every set tells
        # whether to stop ot read further.
        # 0 means keep reading; 1 means thec
        # message is over.
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                if(pix[-1] != 0):
                    pix[-1] -= 1
                else:
                    pix[-1] += 1

        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for pixel in modPix(newimg.getdata(), data):

        # Putting modified pixels in the new image
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

# Encode data into image
def encode(name,key,data,enc_type,text):
    image = Image.open(name, 'r')
    if (len(data) == 0):
        raise ValueError('Data is empty')
    if(enc_type==True):
        data= encrypt_AES(key,data)
    else:
        data =encrypt_bf(key,data)
    newimg = image.copy()
    encode_enc(newimg, data)
    newimg.save(str('static/upload.png'))
    insertBLOB(session['username'],key,'static/upload.png',enc_type,text)
    size2=os.stat('static/upload.png').st_size
    # os.rename('upload.png', 'static/upload.png')
    # shutil.move('upload.png', 'static/upload.png')
    # os.replace('upload.png', 'static/upload.png')
    return size2
    

# Decode the data in the image
def decode(name,key,enc_type):
    conn = sqlite3.connect('registerDB.db')
    cur = conn.cursor()
    print(name)
    print(key)
    name1='"'+name+'"'
    cur.execute('SELECT * FROM REGISTER WHERE NAME ='+'"'+name+'"')
    account = cur.fetchone()
    img1 = account[4]
    key = account[5]
    img='image.png'
    writeTofile(img1,img)
    image = Image.open(img, 'r')
    data = ''
    imgdata = iter(image.getdata())

    while (True):
        pixels = [value for value in imgdata.__next__()[:3] +
                                imgdata.__next__()[:3] +
                                imgdata.__next__()[:3]]

        # string of binary data
        binstr = ''

        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'

        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0):
            if(enc_type==True):
                data=decrypt_AES(key,data)
            else:
                data=decrypt_bf(key,data)
            os.remove('image.png')
            return data
        
def encrypt_AES(keyHex,data):
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("aes")
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(8)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")
    crypt.SetEncodedKey(keyHex,"hex")
    encStr = crypt.encryptStringENC(data)
    return encStr

def decrypt_AES(keyHex,data):
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("aes")
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(8)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")
    crypt.SetEncodedKey(keyHex,"hex")
    decStr = crypt.decryptStringENC(data)
    return decStr
def encrypt_bf(keyHex,data):
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("blowfish2")
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(8)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")
    crypt.SetEncodedKey(keyHex,"hex")

    encStr = crypt.encryptStringENC(data)
    return encStr

def decrypt_bf(keyHex,data):
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("blowfish2")
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(8)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")
    crypt.SetEncodedKey(keyHex,"hex")
    decStr = crypt.decryptStringENC((data))
    return decStr

@app.route('/')
def home():
    return redirect(url_for('login'))
@app.route('/loggedIN',methods=['POST','GET'])
def loggedIN():
    return render_template('index_code.html',msg=session['username'])
@app.route('/register',methods=['POST','GET'])
def register():
    if request.method == 'POST' and 'email' in request.form and 'pw' in request.form and 'name' in request.form:
        d=request.form
        conn = sqlite3.connect('registerDB.db')
        cur = conn.cursor()
        password = d['pw'].encode("utf-8")
        password = base64.b64encode(password)
        cur.execute('INSERT INTO REGISTER  (name, email,password) VALUES (?, ?, ?)',(d['name'],d['email'],encoded))
        cur.execute('SELECT name, email FROM REGISTER')
        for row in cur:
            print(row)
        conn.commit()
        conn.close()
        return render_template('index_login.html')
    return render_template('index_signup.html')
@app.route('/login',methods=['POST','GET'])
def login():
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'email' in request.form and 'pw' in request.form:
        # Create variables for easy access
        username = request.form['email']
        password = request.form['pw']
        # Check if account exists using MySQL
        print(username)
        print(password)
        conn = sqlite3.connect('registerDB.db')
        cur = conn.cursor()
        password = password.encode("utf-8")
        password = base64.b64encode(password)
        cur.execute('SELECT * FROM REGISTER WHERE email = ? AND password = ?', (username, ))
        # Fetch one record and return result
        account = cur.fetchone()
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['username'] = account[1]
            print("success")
            return redirect(url_for('loggedIN'))
        else:
            # Account doesnt exist or username/password incorrect
            print("fail")
            msg = 'Incorrect username/password!'
    
    return render_template('index_login.html', msg=msg)

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))
@app.route('/encode_image',methods=['POST','GET'])
def encode_image():
    message=''
    if request.method == 'POST':
        f = request.files['file']  
        f.save(f.filename)
        size1=os.stat(f.filename).st_size
        if(request.form['enc']=="aes"):
            print(request.form['enc']+"encode")
            size2=encode(f.filename,request.form['key'],request.form['message'],True,request.form['message'])
        else:
            print(request.form['enc']+"encode")
            size2=encode(f.filename,request.form['key'],request.form['message'],False,request.form['message'])
        print(request.form['message'])
        print(request.form['enc'])
        print(f.filename)
        os.remove(f.filename)
        print(os.getcwd()+'\ upload.png');
        return render_template('index_encode.html',message="Image encoded successfully",size1="Size of the original Image: "+str(size1)+" bytes",size2="Size of the encrypted Image: "+str(size2)+" bytes",image_dir=os.getcwd()+"\ upload.png");
    return render_template('index_encode.html')
@app.route('/decode_image',methods=['POST','GET'])
def decode_image():
    message=''
    name=session['username']
    conn = sqlite3.connect('registerDB.db')
    cur = conn.cursor()
    cur.execute('SELECT * FROM REGISTER WHERE NAME ='+'"'+name+'"')
        # Fetch one record and return result
    account = cur.fetchone()
    if(account[6]=="1"):
        enc=True
        if request.method == 'POST':
            message=decode(session['username'],request.form['key'],enc)
            return render_template('decode_image.html',enc="AES",message='The decoded message is: '+message)
        return render_template('decode_image.html',enc="AES")
    else:
        enc=False
        if request.method == 'POST':
            message=decode(session['username'],request.form['key'],enc)
            return render_template('decode_image.html',enc="BlowFish",message='The decoded message is: '+message)
        return render_template('decode_image.html',enc="BlowFish")
    # return render_template('decode_image.html')

    
if __name__ == '__main__':
    app.run()