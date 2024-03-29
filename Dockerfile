# Use an ARM64-compatible base image
FROM ubuntu:20.04

# Set environment variables to avoid prompts during installations
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install essential packages
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    gnupg \
    software-properties-common \
    git \
    neovim \
    vim

# Install Python 3.10
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.10 python3.10-distutils

# Set Python 3.10 as the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# Install pip for Python 3.10
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3.10 get-pip.py && \
    rm get-pip.py

# Install AWS CLI for ARM64
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf aws awscliv2.zip

# Install Azure CLI for ARM64
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Download and install Terraform for ARM64
RUN wget https://releases.hashicorp.com/terraform/1.6.6/terraform_1.6.6_linux_arm64.zip -O terraform.zip && \
    unzip terraform.zip && \
    mv terraform /usr/local/bin/ && \
    rm terraform.zip

# Install Helm for ARM64
RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && \
    chmod +x get_helm.sh && \
    ./get_helm.sh && \
    rm get_helm.sh

# Install kubectl for ARM64
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Install Docker for ARM64 without using 'add-apt-repository'
RUN apt-get update && apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    echo "deb [arch=arm64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io

# Create a user called "crowdstrike" with password "crowdstrike"
RUN useradd -ms /bin/bash crowdstrike
RUN echo 'crowdstrike:crowdstrike' | chpasswd

# Create folders
RUN mkdir -p /crowdstrike
RUN mkdir -p /crowdstrike/abstrakt
RUN mkdir -p /crowdstrike/abstrakt/conf
RUN mkdir -p /crowdstrike/abstrakt/terraformModules
RUN mkdir -p /tmp/crowdstrike
RUN mkdir -p /root/.aws
RUN mkdir -p /root/.bash_completions
RUN touch /root/.aws/credentials
RUN mkdir -p /home/crowdstrike/.aws
RUN touch /home/crowdstrike/.aws/credentials

COPY ./dist/abstrakt-0.1.0-py3-none-any.whl /tmp/crowdstrike/
COPY ./abstrakt/conf /crowdstrike/abstrakt/conf
COPY ./abstrakt/terraformModules /crowdstrike/abstrakt/terraformModules
COPY abstrakt.sh /root/.bash_completions/abstrakt.sh

RUN python3.10 -m pip install pytz
RUN python3.10 -m pip install pydantic
RUN python3.10 -m pip install azure
RUN python3.10 -m pip install azure-identity
RUN python3.10 -m pip install kubernetes
RUN python3.10 -m pip install /tmp/crowdstrike/abstrakt-0.1.0-py3-none-any.whl

# Add the line to ~/.bashrc
# RUN echo 'abstrakt --install-completion' >> /home/crowdstrike/.bashrc
RUN echo 'source /root/.bash_completions/abstrakt.sh' >> /root/.bashrc

# Give "crowdstrike" user read/write access to /var directory
RUN chown -R crowdstrike:crowdstrike /var
RUN chown -R crowdstrike:crowdstrike /crowdstrike
RUN chown -R crowdstrike:crowdstrike /home
RUN chown -R crowdstrike:crowdstrike /tmp

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the working directory to the "kitbash" folder
WORKDIR /crowdstrike
