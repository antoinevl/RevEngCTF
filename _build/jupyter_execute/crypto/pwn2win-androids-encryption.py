# Androids Encryption

## Introduction

__Solved by__: [hyperc](https://twitter.com/hyperc54).

__Event__: Pwn2Win 2020: [https://ctftime.org/event/961](https://ctftime.org/event/961)

__Challenge name__: Androids Encryption (115 pts)

__Description__: We intercept an algorithm that is used among Androids. There are many hidden variables. Is it possible to recover the message?

__File__: `server.py`

## Encryption logic

The challenge was accessible on a remote server which provided us with two options:
* Get an encrypted version of a plaintext provided by the user
* Get an encrypted version of the flag
    
The Python implementation of the server was also provided in `server.py` and allowed us to understand the logic behind the encryption method.

The main method of this app is the `encrypt` function. 

Given a plaintext, a key and an initialisation vector (IV), it:
* Encrypts the plaintext using AES algorithm in a CBC fashion but with a little twist. 
* Returns the ciphertext concatenated with the IV used.

```
def encrypt(txt, key, iv):
    global key2, iv2
    assert len(key) == BLOCK_SIZE, f'Invalid key size'
    assert len(iv) == BLOCK_SIZE, 'Invalid IV size'
    assert len(txt) % BLOCK_SIZE == 0, 'Invalid plaintext size'
    bs = len(key)
    blocks = to_blocks(txt)
    ctxt = b''
    aes = AES.new(key, AES.MODE_ECB)
    curr = iv
    for block in blocks:
        ctxt += aes.encrypt(xor(block, curr))
        curr = xor(ctxt[-bs:], block)
    iv2 = AES.new(key2, AES.MODE_ECB).decrypt(iv2)
    key2 = xor(to_blocks(ctxt))
    return str(base64.b64encode(iv+ctxt), encoding='utf8')
```

which can be illustrated by the following diagram:

![](../_images/android-encryption-1.png)

The `encrypt` function also does another important thing: it modifies two global variables, `iv2` and `key2` that are exactly the key and initialisation vector used by the application to return an encrypted version of the flag to the user.

```
key2 = xor(to_blocks(ctxt))
```

Hence, `key2` is reinitialised after each encryption to the result of our previous encryption, which we obviously have. 

Since this type of encryption is symmetric, getting `key2` enables us to decrypt the encrypted flag.

## Step by step

### Send a random plaintext to the server and get the response ciphertext

response1 = 'qal7b3mi7fEvSccj+NcaYtqU4i4io4qT1g88K9wY2nQ='
iv_plus_ctext = base64.b64decode(response1)
ctext = al[16:] # IV is 16 bytes long

### Get key2 from the recevied ciphertext

key2 = xor(to_blocks(ctext))

### Query the encrypted flag from the server

enc_flag = '36X0Ug8ZEIvrRDeus6c3GBynEY7La36H0/A1Bqoy87go8FyYOeRQOuN7b0fXJXMYqWZ9lo9MWkS8EaN9/8Tl7A=='
enc_flag = base64.b64decode(enc_flag)

### Decrypt the ciphertext following the diagram above

from Crypto.Cipher import AES

iv2 = enc_flag[:16] 
c1 = enc_flag[16:32]
c2 = enc_flag[32:48]
c3 = enc_flag[48:64]

aes = AES.new(key2, AES.MODE_ECB)

p1 = xor(aes.decrypt(c1),iv2)
p2 = xor(aes.decrypt(c2),xor(c1,p1))
p3 = xor(aes.decrypt(c3),xor(c2,p2))

### And find the flag!

assert(p1+p2+p3 == b'CTF-BR{kn3W_7h4T_7hEr3_4r3_Pc8C_r3pe471ti0ns?!?}')