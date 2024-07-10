# Use the latest Ubuntu base image
FROM ubuntu:20.04

# Install curl, telnet, iputils-ping, and net-tools
RUN apt-get update && \
    apt-get install -y curl telnet iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*  # Clean up to reduce image size
