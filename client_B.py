# Description: Client B qui reçoit des messages sécurisés de A via MQTT.
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import paho.mqtt.client as mqtt
import os
import traceback


# Charger la vraie clé privée de B
with open("privkey_B.pem", "rb") as f:
    private_key_B = serialization.load_pem_private_key(f.read(), password=None)

# Clé publique de la CA (connue en dur)
with open("cert_ca.json", "r") as f:
    cert_CA = json.load(f)

pubkey_CA = serialization.load_pem_public_key(base64.b64decode(cert_CA["public_key"]))


def verify_cert(cert):
    pub_key_bytes = base64.b64decode(cert["public_key"])
    signature = base64.b64decode(cert["signature"])
    try:
        pubkey_CA.verify(
            signature,
            pub_key_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return serialization.load_pem_public_key(pub_key_bytes)
    except Exception as e:
        print("[B] Échec de vérification du certificat :", e)
        traceback.print_exc()
        return None

def dechiffrer_sym(data, key):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

def dechiffrer_asym(data, privkey):
    return privkey.decrypt(
        data,
        padding.PKCS1v15()
    )

def verifier_signature(message, signature, pubkey):
    pubkey.verify(
        signature,
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

# MQTT
def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        if data.get("type") == "secure_message" and data.get("dest") == "B":
            print("[B] Message sécurisé reçu de", data["source"])

            cert_A = data["certificate"]
            pubkey_A = verify_cert(cert_A)
            if not pubkey_A:
                print("[B] Certificat invalide")
                return

            encrypted_key = base64.b64decode(data["encrypted_key"])
            ciphertext = base64.b64decode(data["ciphertext"])
            signature = base64.b64decode(data["signature"])

            sym_key = dechiffrer_asym(encrypted_key, private_key_B)
            message = dechiffrer_sym(ciphertext, sym_key).decode()

            verifier_signature(message, signature, pubkey_A)
            print("[B] Message vérifié et déchiffré :", message)
    except Exception as e:
        print("[B] Erreur :", e)
    traceback.print_exc()

client = mqtt.Client()
client.on_message = on_message
client.connect("194.57.103.203", 1883, 60)
client.subscribe("vehicles_ahai_qtri")
client.loop_forever()
