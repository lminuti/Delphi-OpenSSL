@echo off
openssl smime -sign -in TestPKCS7.pdf -binary -signer publiccert.pem -inkey privatekey.pem -out TestPKCS7.pdf.p7m -outform DER -nodetach