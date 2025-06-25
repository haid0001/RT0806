import json 
import base64
import paho.mqtt.client as mqtt
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import sys


NODE_NAME = sys.argv[1] if len(sys.argv) > 1 else "A"
received_certificate = None

#geration des cles pour le client
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Sauvegarde de la clé privée
with open(f"privkey_{NODE_NAME}.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))


def get_public_key_pem():
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

#MQTT Callbacks
def on_connect(client, userdata, flags, rc):
    print(f"[{NODE_NAME}] Client connecté au broker avec le code: {rc}")
    client.subscribe("vehicles_ahai_qtri")
    send_certificate_request(client)

def on_message(client, userdata, msg):
    global received_certificate
    try:
        print(f"[{NODE_NAME}] Message brut reçu sur MQTT:")
        print(msg.payload.decode())  # Affichage brut

        data = json.loads(msg.payload.decode())
        print(f"[{NODE_NAME}] Message décodé:", data)  # Pour debug

        if data.get("type") == "cert_response" and data.get("dest") == NODE_NAME:
            print(f"[{NODE_NAME}] Certificat reçu de la CA.")
            received_certificate = data["certificate"]
            client.loop_stop()
    except Exception as e:
        print(f"[{NODE_NAME}] Erreur dans le message:", e)

#envoi de la demande de certificat
def send_certificate_request(client):
    pub_pem = get_public_key_pem()
    payload = {
        "type": "cert_request",
        "source": NODE_NAME,
        "public_key": base64.b64encode(pub_pem).decode()
    }
    client.publish("vehicles_ahai_qtri", json.dumps(payload))
    print(f"[{NODE_NAME}] Demande de certificat envoyée")

#l  ancement du client MQTT

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("194.57.103.203", 1883, 60)
client.loop_start()

while received_certificate is None:
    print(f"[{NODE_NAME}] En attente de certificat...")
    time.sleep(1)

print(f"[{NODE_NAME}] Certificat reçu: {received_certificate}")

with open(f"cert_{NODE_NAME}.json", "w") as f:
    json.dump(received_certificate, f)

print(f"[{NODE_NAME}] Certificat sauvegardé dans cert_{NODE_NAME}.json")