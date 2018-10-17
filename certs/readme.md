# RSA Signatures - Certificates (without passphrase)
Demo certificates `private.key` and `public.key` where generated with http://travistidwell.com/jsencrypt/demo/

# RSA Signatures - Certificates (with passphrase)
Demo certificates `private.pem` and `public.pem` where generated with the following command lines

```bash
# that generate a 2048-bit RSA key pair, and encrypts them with a passphrase
# the passphrase I choose for the demo files is: super secret passphrase
openssl genrsa -des3 -out private.pem 2048

# we export the RSA public key to a file
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```
