@echo off
openssl req -x509 -nodes -newkey rsa:2048 -keyout privatekey.pem -out publiccert.pem -days 500
openssl x509 -pubkey -noout -in publiccert.pem  > publickey.pem