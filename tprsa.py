#!/usr/bin/python3

# tprsa.py
# authors: John Schanck, Sam Jaques
# license: CC0 / public domain
#
# PNG-encoded multi-power RSA-4341760.
#
# tprsa stands for "Tweetable PNG RSA"
# ..... or maybe Truly Powerful RSA
# ..... or maybe Totally Paranoid RSA

from functools import reduce

from gmpy2 import is_prime as isPrime
from gmpy2 import invert as invModPrime
from gmpy2 import mpz

import os
import hashlib
import pickle

from PIL import Image, ImageDraw, ImageFont

# Keys and ciphertexts are
BLEN = (1060 * 4096 // 8 + 6)//7 * 7
# bytes. Note sum([2,3,5,7,...,97]) = 1060,
# we use 4096-bit primes, we encode 7 bits per byte
# and zero pad to a 7 byte boundary

def getRand4096():
    a = int.from_bytes(os.urandom(512), byteorder="little")
    a |= 2**4095
    return a

def getPrime4096():
    print(".",end="",flush=True)
    # X and Y are used to round to a value that is
    # 2 mod 3 and 1 mod p for p | Y, p!=3.
    X = 5 #1537045309297012283168734764887837381
    Y = 6 #2305567963945518424753102147331756070
    a = getRand4096()
    a = a + (X - (a%Y))
    while not isPrime(a): # 25 Miller-Rabin tests
        a = getRand4096()
        a = a + (X - (a%Y))
    return a

def invModPrimePow(a, p, e):
    print(".",end="",flush=True)
    P = p**e
    b = int(invModPrime(a, p))
    f = 1
    while f < e:
        b = (b * (2 - a*b)) % P
        f = 2*f
    return b

def cubeRootModPrimePow(a, p, e):
    print(".",end="",flush=True)
    # assume p = 2 mod 3
    dp = (2*p-1)//3
    x = pow(mpz(a), dp, p)
    f = 1
    P = p*p
    while f < e:
        x = (x - (x**3 - a) * invModPrimePow(3*x**2, p, f)) % P
        f = 2*f
        P = P*P
    x = x % (p**e)
    return int(x)

def key(privatefn, publicfn):
    ps = [getPrime4096() for _ in range(25)]
    es = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, \
          43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    print(" done primegen")
    Ps = [p**e for (p, e) in zip(ps, es)]
    N = reduce(lambda x, y: x*y, Ps)
    N0 = [N//P for P in Ps]
    X = [invModPrimePow(m, p, e) for (m, p, e) in zip(N0, ps, es)]
    print(" done keygen")
    private = (ps, X, N)
    public = N.to_bytes(BLEN, byteorder="little")
    with open(privatefn, "wb") as jar:
        pickle.dump(private, jar)
    writeBytesToPNG(encode7bit(public), publicfn)
    return True

def encaps(publicfn, ctxtfn):
    public = decode7bit(readBytesFromPNG(publicfn))
    N = int.from_bytes(public, byteorder="little")
    numbytes = len(public)-1
    while public[numbytes] == 0:
        numbytes -= 1
    numbytes -= 1
    rbar = os.urandom(numbytes)
    rbar += b'\0' * (BLEN - numbytes)
    H = hashlib.sha3_256()
    H.update(rbar)
    k = H.digest()
    r = int.from_bytes(rbar, byteorder="little")
    C = int(pow(mpz(r), 3, N))
    Cbar = C.to_bytes(BLEN, byteorder="little")
    writeBytesToPNG(encode7bit(Cbar), ctxtfn)
    return k

def decaps(privatefn, ctxtfn):
    with open(privatefn, "rb") as jar:
        private = pickle.load(jar)
    ciphertext = decode7bit(readBytesFromPNG(ctxtfn))
    C = int.from_bytes(ciphertext, byteorder="little")
    (ps, Xs, N) = private
    if C >= N:
        print("malformed ciphertext")
        return
    es = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, \
         43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    Rs = [cubeRootModPrimePow(C, p, e) for (p,e) in zip(ps,es)]
    print(" done roots")
    Ps = [p**e for (p,e) in zip(ps, es)]
    r = 0
    for (R,X,P) in zip(Rs,Xs,Ps):
        print(".",end="",flush=True)
        r += (N//P) * ((R*X)%P)
    print(" done crt")
    r %= N
    rbar = r.to_bytes(BLEN, byteorder="little")
    H = hashlib.sha3_256()
    H.update(rbar)
    k = H.digest()
    return k

def encode7bit(w):
    r = b''
    for i in range(0, len(w), 7):
        int56 = int.from_bytes(w[i:i+7], byteorder="little")
        a = []
        while int56 > 0:
            a.append(int56%128)
            int56 = int56//128
        a = [x + 128 for x in a] + [128]*(8-len(a))
        r += b''.join([x.to_bytes(1,byteorder="little") for x in a])
    return r

def decode7bit(w):
    r = b''
    for i in range(0, len(w), 8):
        a = [x&127 for x in w[i:i+8]]
        a = a + [0]*(8-len(a))
        abar = reduce(lambda x,y: 128*x + y, reversed(a), 0)
        r += abar.to_bytes(7, byteorder="little")
    return r

def writeBytesToPNG(data, filename):
    twitter_max_width = 512
    twitter_max_height = 1024
    img_height = 1
    if (len(data) % 4 != 0):
        err('Data length is not a multiple of 4; encoding will require padding')
    total_length = len(data)/4
    img_width = int(total_length/img_height)
    #Pick a nice image size so that there are no
    # padding issues
    while img_width > twitter_max_width:
        for i in range(img_height + 1, twitter_max_height):
            if total_length % i == 0:
                img_height = i
                img_width = int(total_length / img_height)
                break

    img = Image.new('RGBA', (img_width, img_height), color = (255, 255, 255, 128))
    pixels = img.load()

    for i in range(0, len(data), 4):
        pixels[(i/4) % img_width, (i/4) / img_width] = tuple(data[i:i+4])

    img.save(filename, 'png')

def readBytesFromPNG(filename):
    img = Image.open(filename)
    pixels = img.load()
    data = bytes('', 'ascii')
    for i in range(img.size[1]): 
        for j in range(img.size[0]):
            data += bytes(pixels[j,i][0:4])
    return data

def mask(infile, maskfile="tux.png"):
    img = Image.open(infile)
    msk = Image.open(maskfile)
    if img.size[0] != msk.size[0] or img.size[1] != msk.size[1]:
        print("Mask must be the same size as image")
        return
    imgpx = img.load()
    mskpx = msk.load()
    for i in range(img.size[1]): 
        for j in range(img.size[0]):
            tmp = list(imgpx[j,i])
            tmp[0] = (mskpx[j,i][0]&128) | (tmp[0] & 127)
            tmp[1] = (mskpx[j,i][1]&128) | (tmp[1] & 127)
            tmp[2] = (mskpx[j,i][2]&128) | (tmp[2] & 127)
            imgpx[j,i] = tuple(tmp)
    img.save(infile, 'png')

if __name__ == "__main__":
    import sys
    from base64 import b64encode

    usage = \
"""gen: Generate a key.
 $ ./pqrsa.py gen private.pkl public.png

enc: Encrypt a random 32 byte key to public.png.
     Outputs the ciphertext in ciphertext.png,
     and the 32 byte key on stdout.
 $ ./pqrsa.py enc public.png ciphertext.png

dec: Decrypt ciphertext.png.
 $ ./pqrsa.py dec private.pkl ciphertext.png

fingerprint: Print the base64 encoding of the sha3 digest
     of the key or ciphertext in file.png.
 $ ./pqrsa.py fingerprint file.png

mask: Copy the top bits of RGB channels from mask.png into img.png
 $ ./pqrsa.py mask image.png mask.png
"""
    if len(sys.argv) < 3:
        print(usage)
        sys.exit()

    if sys.argv[1] == "fingerprint":
        a = decode7bit(readBytesFromPNG(sys.argv[2]))
        H = hashlib.sha3_256()
        H.update(a)
        print(b64encode(H.digest()).decode("ascii"))
        sys.exit()

    if len(sys.argv) != 4:
        print(usage)
        sys.exit()

    if sys.argv[1] == "gen":
        key(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "enc":
        print(b64encode(encaps(sys.argv[2], sys.argv[3])).decode('ascii'))
    elif sys.argv[1] == "dec":
        print(b64encode(decaps(sys.argv[2], sys.argv[3])).decode('ascii'))
    elif sys.argv[1] == "mask":
        mask(sys.argv[2], sys.argv[3])
    else:
        print(usage)
    sys.exit()
