import socket
import json
import os
import hashlib

HOST = 'localhost'
PORT = 9003

subscriber_db = {
    "suci_001": "long_term_secret_key"
}

def generate_auth_vector(suci):
    print("\n[UDM] Authentication Vector Generation Started")
    print("Long-Term Secret Key (K) =", subscriber_db[suci])
    print("Generating RAND using OS Cryptographic Entropy (128-bit secure random)")

    K = subscriber_db[suci]
    RAND = os.urandom(16).hex()

    print("RAND =", RAND)
    print("Computing XRES* = SHA256(K || RAND)")

    XRES = hashlib.sha256((K + RAND).encode()).hexdigest()

    print("XRES* =", XRES)
    print("AUTN = AUTN_TOKEN")

    return {"RAND": RAND, "AUTN": "AUTN_TOKEN", "XRES": XRES}

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("UDM Running...")

conn, addr = server.accept()
data = json.loads(conn.recv(4096).decode())

auth_vector = generate_auth_vector(data["SUCI"])

print("\n[STEP 4] UDM → AUSF : Sending RAND, AUTN, XRES*")

conn.send(json.dumps(auth_vector).encode())
conn.close()
