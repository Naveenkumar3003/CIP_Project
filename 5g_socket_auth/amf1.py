import socket
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

HOST = 'localhost'
PORT = 9001
AUSF_PORT = 9002

# Generate AMF ECC key pair
amf_private_key = ec.generate_private_key(ec.SECP256R1())
amf_public_key = amf_private_key.public_key()

amf_public_bytes = amf_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("AMF Running...")

conn, addr = server.accept()

data = json.loads(conn.recv(4096).decode())

print("\n[STEP 1] UE → AMF : Received SUCI and UE Public Key")

# Contact AUSF
ausf = socket.socket()
ausf.connect((HOST, AUSF_PORT))
ausf.send(json.dumps({"SUCI": data["SUCI"]}).encode())

auth_vector = json.loads(ausf.recv(4096).decode())

print("\n[STEP 6] AMF → UE : Sending RAND, AUTN, AMF Public Key")

conn.send(json.dumps({
    "RAND": auth_vector["RAND"],
    "AUTN": auth_vector["AUTN"],
    "AMF_PUBLIC_KEY": amf_public_bytes
}).encode())

# Receive RES
res_data = json.loads(conn.recv(4096).decode())

print("\n🔑 [AMF] ECC Key Exchange (ECDH)")
print("   Using Curve: SECP256R1")
print("   Mathematical Operation: SharedSecret = d_AMF × Q_UE")

from cryptography.hazmat.primitives.serialization import load_pem_public_key

ue_public_key = load_pem_public_key(data["UE_PUBLIC_KEY"].encode())

shared_secret = amf_private_key.exchange(ec.ECDH(), ue_public_key)

print("   Derived Shared Secret =", shared_secret.hex())
print("   ✔ Shared Secret Established")

print("\n🔐 [AMF] Session Key Derivation")
print("   Formula: K_AMF = SHA256(SharedSecret)")

session_key = hashlib.sha256(shared_secret).hexdigest()

print("   Session Key (K_AMF) =", session_key)

# Forward RES to AUSF
ausf.send(json.dumps(res_data).encode())
result = ausf.recv(4096)

conn.send(result)

ausf.close()
conn.close()
