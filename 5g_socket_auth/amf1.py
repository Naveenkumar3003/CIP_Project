import socket
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

HOST = 'localhost'
PORT = 9001
AUSF_PORT = 9002

amf_private_key = ec.generate_private_key(ec.SECP256R1())
amf_public_key = amf_private_key.public_key()

public_numbers = amf_public_key.public_numbers()
Qx = hex(public_numbers.x)
Qy = hex(public_numbers.y)

print("\n[AMF] Public Key:")
print("Qx =", Qx)
print("Qy =", Qy)

amf_public_bytes = amf_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

amf_sign_private = ec.generate_private_key(ec.SECP256R1())
amf_sign_public = amf_sign_private.public_key()

amf_sign_public_bytes = amf_sign_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("AMF Running...")

conn, addr = server.accept()
data = json.loads(conn.recv(4096).decode())

print("\n[STEP 1] UE -> AMF : Received SUCI (suci_001) and UE Public Key")

ausf = socket.socket()
ausf.connect((HOST, AUSF_PORT))
ausf.send(json.dumps({"SUCI": data["SUCI"]}).encode())
auth_vector = json.loads(ausf.recv(4096).decode())

RAND = auth_vector["RAND"]
AUTN = auth_vector["AUTN"]

print(f"\n[STEP 6] AMF -> UE : Sending RAND ({RAND}), AUTN ({AUTN}), AMF Public Key (Qx={Qx}, Qy={Qy})")

print("\n[AMF] Digital Signature Creation (ECDSA)")
print("Signing Data = RAND + AMF_PublicKey")

message = (RAND + amf_public_bytes).encode()
signature = amf_sign_private.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

print("Signature Generated =", signature.hex())

conn.send(json.dumps({
    "RAND": RAND,
    "AUTN": AUTN,
    "AMF_PUBLIC_KEY": amf_public_bytes,
    "SIGNATURE": signature.hex(),
    "AMF_SIGN_PUBLIC": amf_sign_public_bytes
}).encode())

res_data = json.loads(conn.recv(4096).decode())

print(f"\n[STEP 9] AMF -> AUSF : Forwarding RES* ({res_data['RES']})")

print("\n[AMF] ECC Key Exchange (ECDH)")
print("Using Curve: SECP256R1")
print("Mathematical Operation: SharedSecret = d_AMF × Q_UE")

ue_public_key = load_pem_public_key(data["UE_PUBLIC_KEY"].encode())
shared_secret = amf_private_key.exchange(ec.ECDH(), ue_public_key)

print("Derived Shared Secret =", shared_secret.hex())
print("Shared Secret Established")

print("\n[AMF] Session Key Derivation")
print("Formula: K_AMF = SHA256(SharedSecret)")

session_key = hashlib.sha256(shared_secret).hexdigest()
print("Session Key (K_AMF) =", session_key)

ausf.send(json.dumps(res_data).encode())
result = ausf.recv(4096)

conn.send(result)

ausf.close()
conn.close()
