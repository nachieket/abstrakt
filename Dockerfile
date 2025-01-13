## Use an Ubuntu base image
#FROM ubuntu:24.04
#
## Set environment variables to avoid prompts during installations
#ENV DEBIAN_FRONTEND=noninteractive
#
### Install essential packages and dependencies
#RUN apt-get update \
#    && apt-get install -y --no-install-recommends
#
#RUN apt-get install -y --no-install-recommends \
#    apt-transport-https \
#    curl \
#    wget \
#    unzip \
#    gnupg \
#    lsb-release \
#    sudo \
#    ca-certificates \
#    neovim \
#    vim \
#    libffi-dev \
#    gcc \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
#
#RUN apt-get update \
#    && apt-get install -y --no-install-recommends \
#    software-properties-common \
#    libcairo2-dev \
#    libgirepository1.0-dev \
#    libglib2.0-dev \
#    libgirepository1.0-dev \
#    python3-dev \
#    python3-gi \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
#
## Install build dependencies including make
#RUN apt-get update \
#    && apt-get install -y --no-install-recommends \
#        golang-go \
#        git \
#        libostree-dev \
#        libgpgme-dev \
#        libassuan-dev \
#        libbtrfs-dev \
#        pkg-config \
#        btrfs-progs \
#        libdevmapper-dev \
#        libseccomp-dev \
#        libgpgme11-dev \
#        make \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
#
## Install Python 3.10
##RUN add-apt-repository ppa:deadsnakes/ppa && \
##    apt-get update && \
##    apt-get install -y python3.10 python3.10-distutils && \
##    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
#
## Install Python 3.10
#RUN add-apt-repository ppa:deadsnakes/ppa && \
#    apt-get update && \
#    apt-get install -y python3.10 python3.10-distutils && \
#    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 2 && \
#    update-alternatives --set python3 /usr/bin/python3.10
#
## Install pip for Python 3.10
#RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
#    python3.10 get-pip.py && \
#    rm get-pip.py
#
## Install latest Golang
#RUN curl -fsSL https://golang.org/dl/go1.18.6.linux-amd64.tar.gz | tar -C /usr/local -xz \
#    && export PATH=$PATH:/usr/local/go/bin
#
## Install Skopeo, Podman, and other tools
#RUN apt-get update \
#    && apt-get install -y --no-install-recommends \
#        gnupg \
#        skopeo \
#        podman \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
#
## Install AWS CLI for both architectures
#RUN case $(uname -m) in \
#        x86_64) ARCH=x86_64 ;; \
#        aarch64) ARCH=aarch64 ;; \
#    esac && \
#    curl "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o "awscliv2.zip" && \
#    unzip awscliv2.zip && \
#    ./aws/install && \
#    rm -rf aws awscliv2.zip
#
## Install Azure CLI
#RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash
#
## Download and install Terraform for both architectures
#RUN case $(uname -m) in \
#        x86_64) ARCH=amd64 ;; \
#        aarch64) ARCH=arm64 ;; \
#    esac && \
#    wget "https://releases.hashicorp.com/terraform/1.6.6/terraform_1.6.6_linux_${ARCH}.zip" -O terraform.zip && \
#    unzip terraform.zip && \
#    mv terraform /usr/local/bin/ && \
#    rm terraform.zip
#
## Install Helm for both architectures
#RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && \
#    chmod +x get_helm.sh && \
#    ./get_helm.sh && \
#    rm get_helm.sh
#
## Install kubectl for both architectures
#RUN case $(uname -m) in \
#        x86_64) ARCH=amd64 ;; \
#        aarch64) ARCH=arm64 ;; \
#    esac && \
#    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl" && \
#    chmod +x kubectl && \
#    mv kubectl /usr/local/bin/
#
## Install Docker for both architectures
#RUN apt-get update && apt-get install -y && \
#    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
#    echo "deb [arch=amd64,arm64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
#    apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io
#
## Install Google Cloud CLI
##RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
##    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
##    && apt-get update -y && apt-get install google-cloud-sdk google-cloud-cli-gke-gcloud-auth-plugin -y
#
## Install Google Cloud CLI
##RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
##    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
##    && apt-get update -y \
##    # Force Python 3.10 as the default Python3
##    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 2 \
##    && apt-get install -y google-cloud-sdk google-cloud-cli-anthoscli google-cloud-cli-gke-gcloud-auth-plugin \
#
## Install Google Cloud CLI
##RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
##    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
##    && apt-get update -y \
##    # Make sure Python 3.10 is the default
##    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 9999 \
##    && update-alternatives --set python3 /usr/bin/python3.10 \
##    # Now install Google Cloud SDK
##    && DEBIAN_FRONTEND=noninteractive apt-get install -y google-cloud-sdk google-cloud-cli-gke-gcloud-auth-plugin
#
## Install Google Cloud CLI manually (compatible with any Python version)
##RUN curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-454.0.0-linux-x86_64.tar.gz && \
##    tar -xzf google-cloud-cli-454.0.0-linux-x86_64.tar.gz && \
##    ./google-cloud-sdk/install.sh --quiet && \
##    ln -s /google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud && \
##    rm google-cloud-cli-454.0.0-linux-x86_64.tar.gz
#
## Install Google Cloud CLI manually and include additional components
#RUN curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-454.0.0-linux-x86_64.tar.gz && \
#    tar -xzf google-cloud-cli-454.0.0-linux-x86_64.tar.gz && \
#    ./google-cloud-sdk/install.sh --quiet && \
#    ./google-cloud-sdk/bin/gcloud components install gke-gcloud-auth-plugin --quiet && \
#    ln -s /google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud && \
#    rm google-cloud-cli-454.0.0-linux-x86_64.tar.gz
#
#
## Verify Python version (optional)
## RUN python3 --version
#
## Install saml2aws
#RUN curl -s https://api.github.com/repos/Versent/saml2aws/releases/latest \
#    | grep "browser_download_url.*linux_amd64.tar.gz" \
#    | cut -d '"' -f 4 \
#    | wget -qi - \
#    && tar -xzf saml2aws_*_linux_amd64.tar.gz \
#    && mv saml2aws /usr/local/bin/ \
#    && rm saml2aws*
#
## Create necessary directories
#RUN mkdir -p /crowdstrike/abstrakt/conf /crowdstrike/abstrakt/terraformModules /tmp/crowdstrike /root/.aws /root/.bash_completions /home/crowdstrike/.aws
#
## Copy application files
#COPY ./dist/abstrakt-0.1.0-py3-none-any.whl /tmp/crowdstrike/
#COPY ./abstrakt/conf /crowdstrike/abstrakt/conf
#COPY ./abstrakt/terraformModules /crowdstrike/abstrakt/terraformModules
#COPY abstrakt.sh /root/.bash_completions/abstrakt.sh
#
## Install Python packages
#RUN python3.10 -m pip install --upgrade pip \
#    && python3.10 -m pip install pytz boto3 botocore pathlib requests pydantic azure-identity kubernetes boto3 \
#    cryptography cffi oauthlib azure-mgmt-containerservice azure-mgmt-compute crowdstrike-falconpy pyyaml  \
#    azure-mgmt-containerregistry azure-identity azure-containerregistry pydantic \
#     /tmp/crowdstrike/abstrakt-0.1.0-py3-none-any.whl
#
## Configure bash completion
#RUN echo 'source /root/.bash_completions/abstrakt.sh' >> /root/.bashrc
#
## Set working directory
#WORKDIR /crowdstrike
#
## Default command
#CMD ["/bin/bash"]

# Use an Ubuntu base image
FROM ubuntu:24.04

# Set environment variables to avoid prompts during installations
ENV DEBIAN_FRONTEND=noninteractive

# Install essential tools and dependencies, including Python 3.10
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    curl \
    wget \
    unzip \
    gnupg \
    lsb-release \
    sudo \
    ca-certificates \
    neovim \
    vim \
    libffi-dev \
    gcc \
    software-properties-common && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install additional dependencies for libglib2.0-dev and libcairo2-dev
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2-dev \
    libgirepository1.0-dev \
    libglib2.0-dev \
    gir1.2-glib-2.0 \
    python3-gi && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install build dependencies including make
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        golang-go \
        git \
        libostree-dev \
        libgpgme-dev \
        libassuan-dev \
        libbtrfs-dev \
        pkg-config \
        btrfs-progs \
        libdevmapper-dev \
        libseccomp-dev \
        libgpgme11-dev \
        make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install latest Golang
RUN curl -fsSL https://golang.org/dl/go1.18.6.linux-amd64.tar.gz | tar -C /usr/local -xz \
    && export PATH=$PATH:/usr/local/go/bin

# Add deadsnakes PPA and install Python 3.10 and related packages
RUN apt-get update && apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.10 python3.10-dev python3.10-distutils && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Set Python 3.10 as the default version
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 2 && \
    update-alternatives --set python3 /usr/bin/python3.10

# Install pip for Python 3.10
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3.10 get-pip.py && \
    rm get-pip.py

# Install AWS CLI for both architectures
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CLI_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        CLI_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-${CLI_ARCH}.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf aws awscliv2.zip

# Install Azure CLI
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Add Docker repository and install Docker for both architectures
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    echo "deb [arch=amd64,arm64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce docker-ce-cli containerd.io && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install Terraform for both architectures
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        TERRAFORM_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        TERRAFORM_ARCH="arm64"; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi && \
    curl -fsSL "https://releases.hashicorp.com/terraform/1.6.6/terraform_1.6.6_linux_${TERRAFORM_ARCH}.zip" -o terraform.zip && \
    unzip terraform.zip && \
    mv terraform /usr/local/bin/ && \
    rm terraform.zip

# Install Helm
RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && \
    chmod +x get_helm.sh && \
    ./get_helm.sh && \
    rm get_helm.sh

# Install kubectl for both architectures
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        KUBECTL_ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        KUBECTL_ARCH="arm64"; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${KUBECTL_ARCH}/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Install Google Cloud CLI manually and include additional components
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CLI_ARCH="x86_64"; \
        GCS_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-454.0.0-linux-${CLI_ARCH}.tar.gz"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        CLI_ARCH="arm"; \
        GCS_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-454.0.0-linux-${CLI_ARCH}.tar.gz"; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi && \
    curl -fLO --output-dir /usr/local/ $GCS_URL && \
    tar -xzf /usr/local/google-cloud-cli-454.0.0-linux-${CLI_ARCH}.tar.gz -C /usr/local && \
    /usr/local/google-cloud-sdk/install.sh --quiet && \
    /usr/local/google-cloud-sdk/bin/gcloud components install gke-gcloud-auth-plugin --quiet && \
    ln -s /usr/local/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud && \
    rm -rf /usr/local/google-cloud-cli-454.0.0-linux-${CLI_ARCH}.tar.gz


# Install saml2aws
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        SAML_ARCH="linux_amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        SAML_ARCH="linux_arm64"; \
    else \
        echo "Unsupported architecture: $ARCH"; exit 1; \
    fi && \
    curl -s https://api.github.com/repos/Versent/saml2aws/releases/latest | \
    grep "browser_download_url.*${SAML_ARCH}.tar.gz" | \
    cut -d '"' -f 4 | wget -qi - && \
    tar -xzf saml2aws_*_${SAML_ARCH}.tar.gz && \
    mv saml2aws /usr/local/bin/ && \
    rm saml2aws*

# Install Skopeo, Podman, and other tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gnupg \
        skopeo \
        podman \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create necessary directories
RUN mkdir -p /crowdstrike/abstrakt/conf /crowdstrike/abstrakt/terraformModules /tmp/crowdstrike /root/.aws /root/.bash_completions /home/crowdstrike/.aws

# Copy application files
COPY ./dist/abstrakt-0.1.0-py3-none-any.whl /tmp/crowdstrike/
COPY ./abstrakt/conf /crowdstrike/abstrakt/conf
COPY ./abstrakt/terraformModules /crowdstrike/abstrakt/terraformModules
COPY abstrakt.sh /root/.bash_completions/abstrakt.sh

# Install Python packages
RUN python3.10 -m pip install --upgrade pip && \
    python3.10 -m pip install pytz boto3 botocore pathlib requests pydantic azure-identity kubernetes boto3 \
    cryptography cffi oauthlib azure-mgmt-containerservice azure-mgmt-compute crowdstrike-falconpy pyyaml \
    azure-mgmt-containerregistry azure-identity azure-containerregistry pydantic paramiko pywinrm requests-ntlm \
    /tmp/crowdstrike/abstrakt-0.1.0-py3-none-any.whl

# Configure bash completion
RUN echo 'source /root/.bash_completions/abstrakt.sh' >> /root/.bashrc

# Set working directory
WORKDIR /crowdstrike

# Default command
CMD ["/bin/bash"]
