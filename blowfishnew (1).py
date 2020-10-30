import chilkat

def encrypt_bf():
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("blowfish2")
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(8)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")

    keyHex = input("Enter key: ")
    crypt.SetEncodedKey(keyHex,"hex")

    encStr = crypt.encryptStringENC(input("Enter message: "))
    print(encStr)

def decrypt():
    crypt = chilkat.CkCrypt2()
    crypt.put_CryptAlgorithm("blowfish2")
    crypt.put_CipherMode("cbc")
    crypt.put_KeyLength(8)
    crypt.put_PaddingScheme(0)
    crypt.put_EncodingMode("hex")
    ivHex = "0001020304050607"
    crypt.SetEncodedIV(ivHex,"hex")

    keyHex = input("Enter key: ")
    crypt.SetEncodedKey(keyHex,"hex")
    decStr = crypt.decryptStringENC((input("Enter encrypted text: ")))
    print(decStr)

encrypt_bf()
decrypt()