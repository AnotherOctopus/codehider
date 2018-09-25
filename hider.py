import sys
import argparse
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import requests as reqs

KEYURL = "http://localhost:8000"
pubkfile = "pub"
def hideCode(codefile):
    if not os.path.isfile(pubkfile):
        print("Can't find pubkey file: {}".format(pubkfile))
        sys.exit(1)
    with open(pubkfile,"rb")as fh:
        pubk = RSA.import_key(fh.read())
    with open(codefile,"rb") as fh:
        code = fh.read()
    if len(code) > 20:
        print("you probably encrypted this already")
        sys.exit(1)
    cipher = PKCS1_OAEP.new(pubk)
    encrypted_code = cipher.encrypt(code)
    with open(codefile,"wb") as fh:
        fh.write(base64.b64encode(encrypted_code))
def deencrypt(enc_codefile):
    with open(enc_codefile,"rb") as fh:
        enc_code = base64.b64decode(fh.read())

    if len(enc_code) < 20:
        print("This probably isnt encrypted")
        sys.exit(1)

    try:
        resp = reqs.get(KEYURL)
    except:
        print("Bloop you can't access this site")
        sys.exit(1)
    private_key = RSA.import_key(resp.text)
    cipher = PKCS1_OAEP.new(private_key)
    code = cipher.decrypt(enc_code)
    print("Your code is {}".format(str(code)))
    
def genKey():
    key = RSA.generate(2048)
    private_k = key.export_key()
    with open("index.html","wb+") as fh:
        fh.write(private_k)
    with open(pubkfile,"wb+") as fh:
        fh.write(private_k)
    print("New private public key generated. Upload index.html to your website")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "hide a code from yourself")
    parser.add_argument('-c',type=str,help='The file with the code you want to hide')
    parser.add_argument('-d',type=str,help='deencrypt a file with a website')
    parser.add_argument('-k',action='store_true',help='generate a new pub/privkey')
    args = parser.parse_args()
    if args.c is not None:
        hideCode(args.c)
    elif args.d is not None:
        deencrypt(args.d)
    elif args.k is True:
        genKey()
    else:
        print("Supply an arg")
