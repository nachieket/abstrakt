# Use the latest NGINX base image
FROM ubuntu:20.04

# Install curl, ssh, telnet, and net-tools
RUN apt-get update && \
    apt-get install -y curl telnet iputils-ping net-tools && \
    rm -rf /var/lib/apt/lists/*  # Clean up to reduce image size
