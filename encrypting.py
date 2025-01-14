'''
Encrypting Sensitive Data
'''

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from cryptography.fernet import Fernet

app = FastAPI()

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

class Item(BaseModel):
    plaintext: str
    
class EncryptedItem(BaseModel):
    ciphertext: str
    
@app.post("/encrypt/", response_model=EncryptedItem)
async def encrypt_item(item: Item):
    plaintext = item.plaintext.encode("utf-8")
    ciphertext = cipher_suite.encrypt(plaintext)
    return {"ciphertext": ciphertext.decode("utf-8")}

@app.post("/encrypt/", response_model=EncryptedItem)
async def encrypt_item(item: Item):
    plaintext = item.plaintext.encode("utf-8")
    ciphertext = cipher_suite.encrypt(plaintext)
    return {"ciphertext": ciphertext.decode("utf-8")}