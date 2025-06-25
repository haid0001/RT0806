# sign_cert_C_to_D.py

import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    # Charger la clé privée de C
    with open("privkey_C.pem", "rb") as f:
        private_key_C = serialization.load_pem_private_key(f.read(), password=None)

    # Charger le certificat de C (signé par la CA)
    with open("cert_C.json", "r") as f:
        cert_C = json.load(f)

    # Charger la clé publique de D (fichier PEM)
    with open("pubkey_D.pem", "rb") as f:
        pubkey_D_bytes = f.read()

    # Signer la clé publique de D avec la clé privée de C
    signature = private_key_C.sign(
        pubkey_D_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Construire le certificat de D signé par C
    cert_D = {
        "public_key": base64.b64encode(pubkey_D_bytes).decode(),
        "signature": base64.b64encode(signature).decode(),
        "issuer_cert": cert_C  # certificat de C signé par la CA
    }

    # Sauvegarder dans cert_D_from_C.json
    with open("cert_D_from_C.json", "w") as f:
        json.dump(cert_D, f)

    print(" cert_D_from_C.json généré avec succès.")

except Exception as e:
    print(" Erreur :", e)
