# Certificates generation

## RSA Signatures - Certificates (without passphrase)
Demo certificates `private.key` and `public.key` where generated with http://travistidwell.com/jsencrypt/demo/

## RSA Signatures - Certificates (with passphrase)
Demo certificates `private.pem` and `public.pem` where generated with the following command lines

```sh
# we generate a 2048-bit RSA key pair, and encrypts them with a passphrase
# the passphrase I choose for the demo files is: super secret passphrase
openssl genrsa -des3 -out private.pem 2048

# we export the RSA public key to a file
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

## ECDSA Signatures - Certificates (without passphrase)
Demo certificates `privateECDSA.key` and `publicECDSA.key` where generated with the following command lines

```sh
# we generate a P-256 curve ECDSA key pair
openssl ecparam -genkey -name secp256k1 -out privateECDSA.key

# we export the ECDSA public key to a file
openssl ec -in privateECDSA.key -pubout -out publicECDSA.key
```

## ECDSA Signatures - Certificates (with passphrase)
Demo certificates `privateECDSA.pem` and `publicECDSA.pem` where generated with the following command lines

```sh
# we generate a P-256 curve ECDSA key pair, and encrypts them with a passphrase
# the passphrase I choose for the demo files is: super secret passphrase
openssl ecparam -genkey -name secp256k1 | openssl ec -aes256 -out privateECDSA.pem

# we export the ECDSA public key to a file
openssl ec -in privateECDSA.pem -pubout -out publicECDSA.pem
```
