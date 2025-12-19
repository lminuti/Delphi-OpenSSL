@echo off
openssl req -x509 -nodes -newkey rsa:2048 -keyout privatekey.pem -out publiccert.pem -days 3650 -config openssl-temp.cfg
openssl x509 -pubkey -noout -in publiccert.pem > publickey.pem 