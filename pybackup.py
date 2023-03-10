#!/usr/bin/python3

import os
import argparse
import subprocess
import binascii

def execute_command(fields):
    p = subprocess.Popen(fields, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    print(out)
    return [out, err]

def backup():
    gen_temp_keys()
    derive_shared_secret()
    encrypt("old.sh", "old.tar.zst")
    gen_hmac()
    #clean_backup()
    pass

def restore():
    derive_shared_secret()
    verify_hmac()
    #decrypt("old.sh", "old.tar.zst")
    #clean_restore()
    pass

def read_secret_key():
    binFile = open('SharedSecret.bin','rb')
    binaryData = binFile.read(32)
    hex = binascii.hexlify(binaryData).decode('ascii')
    return hex

def clean_backup():
    os.unlink("temp-private.pem")
    os.unlink("SharedSecret.bin")

def verify_hmac():
    hex = read_secret_key()
    command1 = ['openssl', 'mac', '-macopt', 'hexkey:' + hex, '-in', 'old.tar.zst', '-out', 'old.tar.zst.hmac-verify', 'POLY1305']
    execute_command(command1)
    pass
    
def gen_hmac():
    hex = read_secret_key()
    print(hex)
    #os.unlink("old.tar.zst.hmac")
    command1 = ['openssl', 'mac', '-macopt', 'hexkey:' + hex, '-in', 'old.tar.zst', '-out', 'old.tar.zst.hmac', 'POLY1305']
    execute_command(command1)

def encrypt(infile, outfile):
    command1 = 'tar -cf - old.sh  | zstd -3cv -T4 | openssl enc -chacha20 -in - -out old.tar.zst -pass file:HashedSharedSecret -pbkdf2'
    ps = subprocess.Popen(command1,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    out, err = ps.communicate()
    pass

def derive_shared_secret():
    command1 = ['openssl', 'pkeyutl', '-derive', '-inkey', 'temp-private.pem', '-peerkey', 'masterkey-public.pem', '-out', 'SharedSecret.bin']
    execute_command(command1)
    command2 = ['openssl', 'dgst', '-sha256', '-out', 'HashedSharedSecret', 'SharedSecret.bin']
    execute_command(command2)
    
def gen_temp_keys():
    command1 = ['openssl', 'ecparam', '-genkey', '-param_enc', 'explicit', '-out', 'temp-private.pem', '-name', 'secp256k1']
    execute_command(command1)                                                                                                         
    command2 = ['openssl', 'pkey', '-in', 'temp-private.pem', '-pubout', '-out', 'temp-public.pem']
    execute_command(command2) 
    pass           

def masterkey():
    command1 = ['openssl', 'ecparam', '-genkey', '-param_enc', 'explicit', '-out', 'masterkey-private.pem', '-name', 'secp256k1']
    execute_command(command1)
    command2 = ['openssl', 'pkey', '-in', 'masterkey-private.pem', '-pubout', '-out', 'masterkey-public.pem']
    execute_command(command2)
    pass

def main():
    parser = argparse.ArgumentParser(description = "pybackup!")

    parser.add_argument("-b", "--backup", type = str, nargs = 1,
        help = "makes backup.")
    
    parser.add_argument("-r", "--restore", type = str, nargs = 1,
        help = "restores backup.")
    
    parser.add_argument("-p", "--masterkey", type = str, nargs = 1,                                                                           help = "generates secret master key pair")

    args = parser.parse_args()

    if args.backup != None:
        backup()
    elif args.masterkey != None:
        masterkey()
    elif args.restore != None:
        restore()
    pass

if __name__ == "__main__":
    main()

#    Generate a temporary EC private key using openssl ec
#    Use the recipient's public key to derive a shared secret using openssl pkeyutl
#    Encrypt the plaintext using openssl enc using the derived secret key
#    Generate the EC public key from the private key using openssl ecparam
#    Generate the HMAC of the cipher text into a third file using openssl dgst
#    Delete the EC private key and the shared secret
