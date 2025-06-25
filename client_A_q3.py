import json, base64, traceback
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Charger clé publique de la CA
with open("cert_ca.json", "r") as f:
    cert_CA = json.load(f)

pubkey_CA = serialization.load_pem_public_key(base64.b64decode(cert_CA["public_key"]))

# Déchiffrement symétrique
def dechiffrer_sym(data, key):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

# Déchiffrement asymétrique
def dechiffrer_asym(data, privkey):
    return privkey.decrypt(
        data,
        padding.PKCS1v15()
    )

# Vérification d'une signature
def verifier_signature(message, signature, pubkey):
    pubkey.verify(
        signature,
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

# Vérification en chaîne du certificat de D via C
def verify_chain_cert(cert_D, pubkey_CA):
    try:
        cert_C = cert_D["issuer_cert"]
        pubkey_C_bytes = base64.b64decode(cert_C["public_key"])
        signature_C = base64.b64decode(cert_C["signature"])
        pubkey_CA.verify(signature_C, pubkey_C_bytes, padding.PKCS1v15(), hashes.SHA256())
        pubkey_C = serialization.load_pem_public_key(pubkey_C_bytes)

        pubkey_D_bytes = base64.b64decode(cert_D["public_key"])
        signature_D = base64.b64decode(cert_D["signature"])
        pubkey_C.verify(signature_D, pubkey_D_bytes, padding.PKCS1v15(), hashes.SHA256())
        pubkey_D = serialization.load_pem_public_key(pubkey_D_bytes)

        return pubkey_D
    except Exception as e:
        print("[A] Chaîne de certificat invalide :", e)
        traceback.print_exc()
        return None

# Clé privée de A
with open("privkey_A.pem", "rb") as f:
    private_key_A = serialization.load_pem_private_key(f.read(), password=None)

# MQTT : Réception
def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        if data.get("type") != "secure_message_q3" or data.get("dest") != "A":
            return

        print("[A] Message reçu de", data["source"])

        cert_D = data["certificate"]
        pubkey_D = verify_chain_cert(cert_D, pubkey_CA)
        if not pubkey_D:
            print("[A] Authentification de D échouée.")
            return

        encrypted_key = base64.b64decode(data["encrypted_key"])
        ciphertext = base64.b64decode(data["ciphertext"])
        signature = base64.b64decode(data["signature"])

        sym_key = dechiffrer_asym(encrypted_key, private_key_A)
        message = dechiffrer_sym(ciphertext, sym_key).decode()

        verifier_signature(message, signature, pubkey_D)
        print("[A] Message vérifié et déchiffré :", message)

    except Exception as e:
        print("[A] Erreur :", e)
        traceback.print_exc()

# MQTT
client = mqtt.Client()
client.on_message = on_message
client.connect("194.57.103.203", 1883, 60)
client.subscribe("vehicles_ahai_qtri")
print("[A] En attente de messages de D (Q3)...")
client.loop_forever()
