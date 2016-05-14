@echo off
openssl req -x509 -newkey rsa:2048 -keyout privatekey-pwd.pem -out publiccert-pwd.pem -days 500
openssl x509 -pubkey -noout -in publiccert-pwd.pem  > publickey-pwd.pem