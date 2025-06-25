# Projet PKI – Communication Sécurisée entre Véhicules

Ce projet met en communication des véhicules connectés via le protocole **MQTT**, en utilisant une infrastructure à clé publique (**PKI**).

---

## 🗂 Structure du projet

```
├── ca.py                     # Autorité de Certification (CA)
├── client.py                # Génère clés + demande certificat à la CA (A, B, C, D)
├── client_A.py              # A envoie un message sécurisé à B (Q2)
├── client_B.py              # B reçoit un message sécurisé de A (Q2)
├── client_A_q3.py           # A reçoit un message de D avec certificat signé par C (Q3)
├── client_D_q3.py           # D envoie un message à A avec certificat signé par C (Q3)
├── sign_cert_C_to_D.py      # C signe la clé publique de D (délégation)
├── extract_pubkey_D.py      # Génére pubkey_D.pem à partir de privkey_D.pem
├── cert_*.json              # Certificats de chaque client (signés par CA ou C)
├── privkey_*.pem            # Clés privées de chaque client
├── pubkey_D.pem             # Clé publique de D à faire signer
└── cert_ca.json             # Certificat auto-signé de la CA
```

---

## 🛠 Instructions de test

### ✅ Question 0 – Lancer la CA

```bash
python ca.py
```

- Génère la paire de clés de l’autorité.
- Crée un certificat auto-signé.
- Démarre un serveur MQTT pour écouter les requêtes de certification.

---

### ✅ Question 1 – Demande de certificats

```bash
python client.py A
python client.py B
python client.py C
python client.py D
```

Chaque client :
- Génère sa paire de clés RSA.
- Envoie une demande de certificat à la CA.
- Reçoit et sauvegarde son certificat (`cert_X.json`).

---

### ✅ Question 2 – Message sécurisé de A vers B

1. Lancer d’abord le récepteur :

```bash
python client_B.py
```

2. Ensuite, l’émetteur :

```bash
python client_A.py
```

- A chiffre et signe un message avec ses clés.
- B vérifie la signature et déchiffre le message avec sa clé privée.

---

### ✅ Question 3 – Délégation de certification de C à D

1. Extraire la clé publique de D :

```bash
python extract_pubkey_D.py
```

2. C signe la clé publique de D :

```bash
python sign_cert_C_to_D.py
```

3. Lancer le client A :

```bash
python client_A_q3.py
```

4. Puis le client D (qui utilise le certificat signé par C) :

```bash
python client_D_q3.py
```

---

## ℹ️ Remarques

- Il y a des redondances de code **volontaires** pour rendre chaque question indépendante.
- Cela garantit que chaque étape fonctionne isolément sans altération accidentelle.

---

## 📋 Auteurs

- Projet réalisé dans le cadre du module INFO402.
