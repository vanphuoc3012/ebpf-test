FROM mcr.microsoft.com/devcontainers/go:1.24-trixie

# Install eBPF dependencies during the image build phase
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    make \
    gcc-multilib \
    linux-libc-dev \
    iputils-ping \
    dnsutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*