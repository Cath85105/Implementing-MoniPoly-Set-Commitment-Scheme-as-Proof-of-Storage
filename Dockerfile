# Use a specific Ubuntu version for stability
FROM ubuntu:22.04

# Install essential build tools including g++
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    g++ \
    make \
    python3 \
    git

# Clone the repository
RUN git clone https://github.com/miracl/core.git /core

# Set working directory to cpp implementation
WORKDIR /core/cpp

# Configure and build with all tests using 64-bit configuration
RUN python3 config64.py test

# Set the working directory to the mounted app folder
WORKDIR /app

# Keep container running for inspection (optional)
CMD ["tail", "-f", "/dev/null"]