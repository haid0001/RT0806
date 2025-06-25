# client_A.py
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import paho.mqtt.client as mqtt

# Clé privée et certificat de A déjà générés précédemment
with open("cert_A.json", "r") as f:
    cert_A = json.load(f)

private_key_A = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # à sauvegarder si besoin

# Clé publique de B récupérée de son certificat
with open("cert_B.json", "r") as f:
    cert_B = json.load(f)

pubkey_B = serialization.load_pem_public_key(base64.b64decode(cert_B["public_key"]))

# Fonctions de crypto
def generate_symmetric_key():
    return os.urandom(32)

def chiffrer_sym(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode()) + encryptor.finalize()

def dechiffrer_sym(data, key):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

def signer(message, privkey):
    return privkey.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def chiffrer_asym(data, pubkey):
    return pubkey.encrypt(
        data,
        padding.PKCS1v15()
    )

# Préparer le message
message = "Salut B, ici A."
sym_key = generate_symmetric_key()
chiffre_msg = chiffrer_sym(message, sym_key)
chiffre_key = chiffrer_asym(sym_key, pubkey_B)
signature = signer(message, private_key_A)

payload = {
    "type": "secure_message",
    "source": "A",
    "dest": "B",
    "ciphertext": base64.b64encode(chiffre_msg).decode(),
    "encrypted_key": base64.b64encode(chiffre_key).decode(),
    "signature": base64.b64encode(signature).decode(),
    "certificate": cert_A
}

# Envoi MQTT
client = mqtt.Client()
client.connect("194.57.103.203", 1883, 60)
client.loop_start()
client.publish("vehicles_ahai_qtri", json.dumps(payload))
print("[A] Message sécurisé envoyé à B.")
client.loop_stop()
