import socket
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

HOST = 'localhost'
PORT = 9001

SUCI = "suci_001"
K = "long_term_secret_key"

ue_private_key = ec.generate_private_key(ec.SECP256R1())
ue_public_key = ue_private_key.public_key()

public_numbers = ue_public_key.public_numbers()
Qx = hex(public_numbers.x)
Qy = hex(public_numbers.y)

print("\n[UE] Public Key:")
print("Qx =", Qx)
print("Qy =", Qy)

ue_public_bytes = ue_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

client = socket.socket()
client.connect((HOST, PORT))

print(f"\n[STEP 1] UE -> AMF : Sending SUCI (suci_001) and UE Public Key (Qx={Qx}, Qy={Qy})")

client.send(json.dumps({
    "SUCI": SUCI,
    "UE_PUBLIC_KEY": ue_public_bytes
}).encode())

challenge = json.loads(client.recv(4096).decode())

RAND = challenge["RAND"]
AUTN = challenge["AUTN"]
amf_public_key_pem = challenge["AMF_PUBLIC_KEY"]

print(f"\n[STEP 6] AMF -> UE : Received RAND ({RAND}) and AUTN ({AUTN})")

print(f"\n[STEP 7] UE : Digital Signature Verification on RAND ({RAND})")

signature = bytes.fromhex(challenge["SIGNATURE"])
amf_sign_public_pem = challenge["AMF_SIGN_PUBLIC"]

amf_sign_public = load_pem_public_key(amf_sign_public_pem.encode())
message = (RAND + amf_public_key_pem).encode()

try:
    amf_sign_public.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print("Signature Verified Successfully")
except:
    print("Signature Verification Failed")
    client.close()
    exit()

print("\n[UE] ECC Key Exchange (ECDH)")
print("Using Curve: SECP256R1")
print("Mathematical Operation: SharedSecret = d_UE × Q_AMF")

amf_public_key = load_pem_public_key(amf_public_key_pem.encode())
shared_secret = ue_private_key.exchange(ec.ECDH(), amf_public_key)

print("Derived Shared Secret =", shared_secret.hex())
print("Shared Secret Established")

print("\n[UE] Computing RES*")
print("Formula: RES* = SHA256(K || RAND)")
print("K =", K)
print("RAND =", RAND)

RES = hashlib.sha256((K + RAND).encode()).hexdigest()

print("Computed RES* =", RES)

print(f"\n[STEP 8] UE -> AMF : Sending RES* ({RES})")

client.send(json.dumps({"RES": RES}).encode())

result = client.recv(4096).decode()
print("\nAuthentication Result:", result)

client.close()
