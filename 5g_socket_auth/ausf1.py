import socket
import json

HOST = 'localhost'
PORT = 9002
UDM_PORT = 9003

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)

print("AUSF Running...")

conn, addr = server.accept()
data = json.loads(conn.recv(4096).decode())

print(f"\n[STEP 2] AMF -> AUSF : Authentication Data Request (SUCI={data['SUCI']})")

udm = socket.socket()
udm.connect((HOST, UDM_PORT))

print(f"[STEP 3] AUSF -> UDM : Fetch Subscriber Data (SUCI={data['SUCI']})")

udm.send(json.dumps(data).encode())
auth_vector = json.loads(udm.recv(4096).decode())
udm.close()

print(f"[STEP 5] AUSF -> AMF : Forwarding RAND ({auth_vector['RAND']}), AUTN ({auth_vector['AUTN']})")

conn.send(json.dumps(auth_vector).encode())

res_data = json.loads(conn.recv(4096).decode())

print("\n[AUSF] Verification Phase")
print(f"Received RES* ({res_data['RES']})")
print(f"Stored XRES*  ({auth_vector['XRES']})")
print("Checking RES* == XRES*")

if res_data["RES"] == auth_vector["XRES"]:
    print("RES* Match Confirmed")
    print("Authentication Successful")
    conn.send(b"AUTH_SUCCESS")
else:
    print("Authentication Failed")
    conn.send(b"AUTH_FAILED")

conn.close()
