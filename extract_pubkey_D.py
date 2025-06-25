from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Charger la clé privée de D

with open("privkey_D.pem", "rb") as f:
    privkey = serialization.load_pem_private_key(f.read(), password=None)

pubkey = privkey.public_key()
pem = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("pubkey_D.pem", "wb") as f:
    f.write(pem)

print("pubkey_D.pem généré à partir de privkey_D.pem")
