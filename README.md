# Securing-ML-APIs-with-FastAPI
## create key.pem and cert.pem:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
