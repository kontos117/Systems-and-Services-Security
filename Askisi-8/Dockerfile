# Use the course image as the base
FROM kostasamplia/ransom-lab-ubuntu:2025

# Switch to root to install packages
USER root

# Update and install the missing GMP and OpenSSL development libraries
RUN apt-get update && \
    apt-get install -y libgmp-dev libssl-dev

# Switch back to the student user (optional, but good practice to match the original)
USER student
