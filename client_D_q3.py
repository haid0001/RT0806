# Client D - Envoi d'un message sécurisé à A avec certificat signé par C
import json, base64, os
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Charger la clé privée de D
with open("privkey_D.pem", "rb") as f:
    private_key_D = serialization.load_pem_private_key(f.read(), password=None)

# Charger le certificat de D (signé par C)
with open("cert_D_from_C.json", "r") as f:
    cert_D = json.load(f)

# Charger la clé publique de A
with open("cert_A.json", "r") as f:
    cert_A = json.load(f)

pubkey_A = serialization.load_pem_public_key(base64.b64decode(cert_A["public_key"]))

# Fonctions crypto
def generate_symmetric_key():
    return os.urandom(32)

def chiffrer_sym(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode()) + encryptor.finalize()

def chiffrer_asym(data, pubkey):
    return pubkey.encrypt(data, padding.PKCS1v15())

def signer(message, privkey):
    return privkey.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())

# Construire le message
message = "Salut A, ici D (certifié par C)"
sym_key = generate_symmetric_key()
chiffre_msg = chiffrer_sym(message, sym_key)
chiffre_key = chiffrer_asym(sym_key, pubkey_A)
signature = signer(message, private_key_D)

payload = {
    "type": "secure_message_q3",
    "source": "D",
    "dest": "A",
    "ciphertext": base64.b64encode(chiffre_msg).decode(),
    "encrypted_key": base64.b64encode(chiffre_key).decode(),
    "signature": base64.b64encode(signature).decode(),
    "certificate": cert_D
}

# Envoi via MQTT
client = mqtt.Client()
client.connect("194.57.103.203", 1883, 60)
client.loop_start()
client.publish("vehicles_ahai_qtri", json.dumps(payload))
print("[D] Message sécurisé envoyé à A avec certificat signé par C.")
client.loop_stop()
