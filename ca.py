import json 
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import paho.mqtt.client as mqtt
import time

#gerenation de la paire de clef


ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_public_key = ca_private_key.public_key()

#creation du certificat auto signé 

def create_ca_certificate():
    public_pem = ca_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = ca_private_key.sign(
        public_pem,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return {
        'public_key': base64.b64encode(public_pem).decode('utf-8'),
        'signature': base64.b64encode(signature).decode('utf-8')
    }

def sign_client_key(client_pub_key_pem):
    signature = ca_private_key.sign(
        client_pub_key_pem,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return {
        "public_key": base64.b64encode(client_pub_key_pem).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }

# MQTT Callbacks
def on_connect(client, userdata, flags, rc):
    print("CA connecté au brocker avec le code: " + str(rc))
    client.subscribe("vehicles_ahai_qtri")

    #on punch le certificat auto signé
    ca_cert = create_ca_certificate()
    with open("cert_ca.json", "w") as f:
        json.dump(ca_cert, f)
    print("[CA] Certificat auto-signé sauvegardé dans cert_ca.json")

    client.publish("ca_certificate", json.dumps({
        "type": "ca_certificate",
        "certificate": ca_cert
    }))


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        if data.get("type") == "cert_request":
            print("Demande de certificat reçu")
            pub_key_pem = base64.b64decode(data["public_key"])
            signed_cert = sign_client_key(pub_key_pem)
            reponse = {
                "type": "cert_response",
                "dest": data["source"],
                "certificate": signed_cert
            }
            client.publish("vehicles_ahai_qtri", json.dumps(reponse))
            print("Certificat envoyé")
    except Exception as e:
        print(f"Erreur lors du traitement du message: {e}")


# MQTT Client Setup
mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect("194.57.103.203", 1883, 60)
mqtt_client.loop_forever()