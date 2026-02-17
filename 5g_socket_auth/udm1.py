import socket
import json
import os
import hashlib

HOST = 'localhost'
PORT = 9003

# Subscriber Database
subscriber_db = {
    "suci_001": "long_term_secret_key"
}

def generate_auth_vector(suci):
    print("\n🔐 [UDM] Authentication Vector Generation Started")

    K = subscriber_db[suci]
    print("   Long-Term Secret Key (K) =", K)

    print("   Generating RAND using OS Cryptographic Entropy (128-bit secure random)")
    RAND = os.urandom(16).hex()
    print("   RAND =", RAND)

    print("   Computing XRES* = SHA256(K || RAND)")
    XRES = hashlib.sha256((K + RAND).encode()).hexdigest()
    print("   XRES* =", XRES)

    AUTN = "AUTN_TOKEN"
    print("   AUTN =", AUTN)

    print("\n[STEP 4] UDM → AUSF : Sending RAND, AUTN, XRES*")

    return {"RAND": RAND, "AUTN": AUTN, "XRES": XRES}

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("UDM Running...")

conn, addr = server.accept()
data = json.loads(conn.recv(4096).decode())

auth_vector = generate_auth_vector(data["SUCI"])
conn.send(json.dumps(auth_vector).encode())

conn.close()
