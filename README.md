# TCP Three-Way Handshake (Client-Side) Using Raw Sockets

## Overview
This project implements the **client side** of a simplified TCP three-way handshake using **raw sockets** in C++. A raw socket allows us to manually construct and transmit custom packets at the IP and TCP levels, bypassing the operating system's usual handling of packet fields (sequence numbers, checksums, flags, etc.).

**Objective:**
1. Send an **SYN** packet to the server, specifying a particular sequence number.
2. Receive and validate a **SYN-ACK** response from the server.
3. Send a final **ACK** packet to complete the handshake.

In this assignment, the **server side** is already provided (see the original GitHub [cs425-2025](https://github.com/privacy-iitk/cs425-2025.git) repository in `Homeworks/A3/server.cpp`).  
You only need to compile and run **client.cpp** (this code) to establish a handshake with that server.

---

## Prerequisites and Requirements
1. **Root/Administrator Privileges**: Raw sockets typically require root privileges on Unix-like systems, so you must run this client with `sudo` or as the root user.
2. **C++ Compiler**: A compiler like `g++` that supports C++11 or later is recommended.
3. **Operating System**: A Unix-like environment (Linux or macOS) is typically required for raw socket operations.

---

## Cloning and Building

1. **Clone the Repository**  
   You can download or clone the server's repository (if you need the server side) from:
   ```bash
   git clone https://github.com/privacy-iitk/cs425-2025.git
   ```
   Within that, navigate to cs425-2025/Homeworks/A3 to find server.cpp.

2. **Place or Obtain client.cpp**  
   The client.cpp file (this code) should be placed in the same directory or in a directory of your choice.

3. **Compile**  
   Use the following command to compile client.cpp:
   ```bash
   g++ client.cpp -o client
   ```

4. **Run the Server (Optional)**  
   If you want to test the handshake end-to-end, you must also compile and run the provided server.cpp from the assignment. For example:
   ```bash
   g++ server.cpp -o server
   ./server
   ```
   Make sure to keep the server running in one terminal.

5. **Run the Client**  
   In another terminal (or on another machine), execute the client (requires root privileges):
   ```bash
   sudo ./client
   ```
   The client sends the SYN packet, waits for the SYN-ACK, and if valid, sends the final ACK. The handshake completes with a success message.

## How the Code Works

1. **Raw Socket Creation**
   ```cpp
   int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
   ```
   Creates a raw socket that allows manual manipulation of TCP and IP headers.
   
   Typically needs elevated privileges.

2. **Setting IP_HDRINCL**
   ```cpp
   int one = 1;
   setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
   ```
   Tells the OS kernel that we will include the IP header ourselves, so it should not modify or prepend any IP header fields.

3. **SYN Packet (send_syn)**
   - Constructs an IP header (size 20 bytes, IPv4) and a TCP header (size 20 bytes by default).
   - Sets:
     - Sequence number: 200
     - SYN flag = 1
   - Sends via sendto() to the server's IP and port.

4. **SYN-ACK Reception (receive_syn_ack)**
   - Continuously listens on the raw socket with recvfrom().
   - For each incoming packet:
     - Parse the IP header to get its length.
     - Access the TCP header by offset.
     - Filter packets that are destined for the client port (CLIENT_PORT).
     - Check if SYN and ACK flags are set.
   - Validate:
     - Server's sequence = 400
     - Server's ACK = 200 + 1 = 201

5. **ACK Packet (send_ack)**
   - Constructs a final ACK packet:
     - Sequence number: 600
     - Acknowledgment: 400 + 1 = 401
     - ACK flag = 1
   - Sends it to the server, completing the handshake.

6. **Cleanup**
   - Closes the raw socket at the end.

## Handshake Sequence Numbers
In this simplified assignment, the sequence and acknowledgment numbers must follow a fixed pattern for successful completion:

- Client SYN: Seq = 200
- Server SYN-ACK: Seq = 400, Ack = 201
- Client ACK: Seq = 600, Ack = 401

If these values are incorrect, the server will not accept the handshake.

## Team and Contributions
Team Members:
- Kapu Nirmal Joshua
- Sumay Avi
- Aravind Seshadri

Each contributed 33.3% to the assignment, including design, coding, testing, and documentation.

## Testing
- **Basic Connectivity**: Ensure both client and server are on the same machine or local network. Verify no firewall rules block raw packets.
- **Run Server**: ./server (or use the provided server from the official assignment repository).
- **Run Client**: sudo ./client. Check the console output for:
  - [+] Sent SYN (seq=200)
  - [+] Received SYN-ACK from server...
  - [+] Sent ACK (seq=600, ack=401) -> Handshake complete.
- **Success**: On success, the server logs will confirm the handshake from the client, and the client side will print the final handshake completion message.

## Declaration
We declare that this code and its documentation are our own work. We have not used or provided any unauthorized material. All external references or influences have been properly acknowledged.
