# OQS TLS Server

This project is designed to create a TLS server using the **Open Quantum Safe** (OQS) library. It provides the ability to secure TLS connections using quantum-safe encryption algorithms. The server uses **EPOLL** to manage TLS connections efficiently.

---

## Contents

- [Project Overview](#project-overview)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Configuration](#configuration)
- [Testing](#testing)
- [Notes](#notes)

---

## Project Overview

This project allows you to build a TLS server that supports quantum-safe encryption using **OpenSSL** and **Open Quantum Safe (OQS)** libraries. The server is configured with several key features to ensure secure communication:

- **Session Cache** and **Session Resumption** (TLS Ticket) support.
- Support for **Quantum-safe algorithms** like Kyber, Dilithium, and others.
- **EPOLL** for managing TLS connections efficiently.
- Detailed configuration options for connection timeouts, keep-alive settings, and SSL session management.

### Configuration File: `Config`

The server configuration file `Config` contains various settings to control the server's behavior, such as connection timeouts, session caching, and quantum-safe cryptographic options. You can modify these settings according to your requirements.

Key configurable options include:

- Maximum connections, timeouts, and handshake attempts.
- SSL session cache and session resumption settings.
- Quantum-safe algorithm support (Kyber, Dilithium, etc.).
- Keep-alive settings for maintaining long-running connections.

### SSL Configuration

The server uses the OpenSSL library to manage SSL/TLS connections. Key features include:

1. **Session Cache**: This option enables or disables the session cache, allowing for faster subsequent connections.
2. **Session Resumption**: When enabled, the server can resume sessions using TLS tickets, improving performance.

---

## Dependencies

To build and run this project, you will need the following dependencies:

- **cmake**
- **gcc**
- **libtool**
- **libssl-dev**
- **make**
- **ninja-build**
- **git**

Make sure these are installed before proceeding with the installation steps.

---

## Installation

https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README.md#linux-and-macOS
https://github.com/open-quantum-safe/liboqs/blob/main/CONFIGURE.md#oQS_ALGS_ENABLED

Follow these steps to install the necessary dependencies and set up the project.

### Step 0: Update System and Install Dependencies

First, update your system and install the required packages:

```bash
sudo apt update
sudo apt install cmake gcc libtool libssl-dev make ninja-build git
```

### Step 1: Clone the OpenSSL Repository with OQS Support

Next, clone the OQS-OpenSSL repository with the necessary quantum-safe support:

```bash
cd /usr/local/src
git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git openssl
```

### Step 2: Build and Install the liboqs Library


Note: `You can also add CPU features by enabling specific CPU instruction sets during the configuration. For detailed information, please refer to the https://github.com/open-quantum-safe/liboqs/blob/main/CONFIGURE.md#OQS_USE_CPUFEATURE_INSTRUCTIONS documentation on how to optimize the build for your specific hardware capabilities. This can help improve performance by leveraging hardware-accelerated features supported by your CPU.` 


The `liboqs` library is required to support quantum-safe algorithms. Clone it, build, and install it:

```bash
cd /usr/local/src
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local/src/openssl/oqs -DOQS_USE_OPENSSL=OFF -DOQS_ENABLE_KEM_KYBER=ON -DOQS_ENABLE_SIG_DILITHIUM=ON ..
ninja
sudo ninja install
```

### Step 3: Build OpenSSL with OQS Support

Once `liboqs` is installed, navigate to the OpenSSL directory and configure the build:

linux-aarch64

```bash
cd /usr/local/src/openssl
sudo ./Configure no-shared linux-aarch64 -lm
sudo make -j$(nproc)
```

### Step 4: Install OpenSSL

Finally, install OpenSSL:

```bash
sudo make install
```

---

# Blacklist
A blacklist feature has been implemented to block specific IP addresses from connecting to the server. The blacklist is stored in the file located at `build/security/ip_list_v4.txt.` Each entry in the file consists of a name and an associated IPv4 address, formatted as name;ipv4. The server checks incoming connections against this list, and any matching IP addresses will be rejected.

Example entry in `ip_list_v4.txt`:
```bash
EDirik;192.168.1.100
```
---

# Configuration

The server's configuration is controlled through the `Config` file. Here are some key settings you can adjust:

- **Max Connections**: 
  - Limits the maximum number of concurrent connections to the server.
  
- **Timeouts**: 
  - Set the timeout values for various stages of the connection (e.g., handshake timeout).
  
- **Session Caching**: 
  - Configure whether or not session caching should be used to improve performance for repeat connections. Enabling session caching allows the server to store session information for faster re-establishment of connections, reducing latency for subsequent connections.

- **Session Resumption**: 
  - Supports TLS tickets for resuming SSL/TLS sessions, making the connection process faster.

- **Quantum-safe Algorithms**:
  - Select which quantum-safe algorithms should be enabled for key exchange and signature.

### SSL/TLS Settings

In addition to the general configuration options, the server supports specific SSL/TLS settings:

- **Max Connections**: 
  - Limits the maximum number of concurrent connections to the server.
  
- **Timeouts**: 
  - Set the timeout values for various stages of the connection (e.g., handshake timeout).
  
- **Session Caching**: 
  - Configure whether or not session caching should be used to improve performance for repeat connections. Enabling session caching allows the server to store session information for faster re-establishment of connections, reducing latency for subsequent connections.

- **Quantum-safe Algorithms**:
  - Select which quantum-safe algorithms should be enabled for key exchange and signature.

---

### Testing
To verify that the server is correctly set up, you can test it using the following commands:

### Check OpenSSL Version
Run the following command to check if OpenSSL was successfully installed:

```bash
/usr/local/src/openssl/apps/openssl version
```

### Generate Server Key and Certificate
You can generate a server key and certificate using the quantum-safe signature algorithm:

```bash
openssl req -x509 -new -newkey dilithium2 -keyout server_key.pem -out server_cert.pem -nodes -days 365
```

### Test the TLS Connection
To test the server’s TLS functionality, you can use openssl s_client to connect to your server:

```bash
openssl s_client -connect localhost:4380 -CAfile ./build/certs/server_cert.pem -groups kyber768 -sigalgs dilithium2
```

This will allow you to verify that the server is correctly supporting TLS connections with quantum-safe encryption.

## Notes
- **EPOLL Management:**: 
  - This server uses EPOLL for managing TLS connections. EPOLL is a highly efficient mechanism for handling many connections concurrently, ideal for applications with large numbers of clients.
  
- **Quantum-safe Algorithms**: 
  - The server supports Kyber for key exchange and Dilithium for signatures, both of which are considered quantum-safe and secure against potential quantum attacks.
  
- **SSL/TLS Configuration**: 
  - The SSL/TLS configuration includes options for session caching, session resumption, and quantum-safe cryptography. Make sure to tailor these settings according to your security and performance needs.
