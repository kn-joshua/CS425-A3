#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_PORT 12345    // Must match the server’s listening port.
#define CLIENT_PORT 54321    // Arbitrary client port.

// Constructs and sends a TCP SYN packet with sequence number 200.
// This is the first step of the three-way handshake from the client’s side.
void send_syn(int sock, struct sockaddr_in &server_addr) {
    // The packet will consist of an IP header followed by a TCP header.
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // Cast the beginning of the packet as the IP header structure.
    struct iphdr *ip = (struct iphdr*)packet;
    // Cast the TCP portion (after the IP header) as the TCP header structure.
    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));

    // Fill in the IP header fields.
    ip->ihl = 5;             // IP Header length in 32-bit words (5 x 4 = 20 bytes).
    ip->version = 4;         // IPv4
    ip->tos = 0;             // Type of Service (not used here).
    ip->tot_len = htons(sizeof(packet)); // Total length of IP + TCP headers.
    ip->id = htons(54321);   // Identification field (arbitrary).
    ip->frag_off = 0;        // Fragment offset set to 0 (no fragmentation).
    ip->ttl = 64;            // Time To Live (typical default).
    ip->protocol = IPPROTO_TCP;          // Indicates a TCP packet.
    ip->saddr = inet_addr("127.0.0.1");  // Source IP (client side).
    ip->daddr = server_addr.sin_addr.s_addr;  // Destination IP (server side).

    // Fill in the TCP header fields.
    tcp->source = htons(CLIENT_PORT); // Client’s source port.
    tcp->dest = server_addr.sin_port; // Server’s destination port (SERVER_PORT).
    tcp->seq = htonl(200);            // Client’s SYN sequence number (as required).
    tcp->ack_seq = 0;                // No acknowledgment yet.
    tcp->doff = 5;                   // Data offset: size of the TCP header in 32-bit words.
    tcp->syn = 1;                    // SYN flag set to initiate a connection.
    tcp->ack = 0;                    // ACK flag off for initial SYN.
    tcp->fin = 0;                    // FIN flag off.
    tcp->rst = 0;                    // RST flag off.
    tcp->psh = 0;                    // PSH flag off.
    tcp->urg = 0;                    // URG flag off.
    tcp->window = htons(8192);       // Advertise a typical window size.
    tcp->check = 0;                  // Checksum is initially set to 0 (the kernel may compute it).

    // Send the SYN packet to the server address using raw socket.
    if (sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr*)(&server_addr), sizeof(server_addr)) < 0) {
        perror("sendto() failed for SYN");
        exit(EXIT_FAILURE);
    } else {
        std::cout << "[+] Sent SYN (seq=200)" << std::endl;
    }
}

// Waits for and verifies the SYN-ACK packet from the server.
// This is the second step in the three-way handshake where the server responds
// with both SYN and ACK flags set.
bool receive_syn_ack(int sock) {
    char buffer[65536];  // Buffer for incoming packets (IP + TCP).
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    while (true) {
        // Receive any incoming packet on our raw socket.
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)(&source_addr), &addr_len);
        if (data_size < 0) {
            perror("recvfrom() failed");
            continue;  // Keep listening if a receive error occurs.
        }

        // Interpret the received data as IP header first.
        struct iphdr *ip = (struct iphdr*)buffer;
        unsigned int ip_header_len = ip->ihl * 4;  // IP header length in bytes.
        // Next, interpret the remainder as a TCP header.
        struct tcphdr *tcp = (struct tcphdr*)(buffer + ip_header_len);

        // Filter out packets that are not destined for our client port (CLIENT_PORT).
        if (ntohs(tcp->dest) != CLIENT_PORT)
            continue;

        // Debug logs: Print out the received TCP flags and sequence number.
        std::cout << "[+] TCP Flags: "
                  << " SYN: " << tcp->syn
                  << " ACK: " << tcp->ack
                  << " FIN: " << tcp->fin
                  << " RST: " << tcp->rst
                  << " PSH: " << tcp->psh
                  << " SEQ: " << ntohl(tcp->seq) << std::endl;

        // Check if the received packet is indeed a SYN-ACK (both flags set).
        if (tcp->syn == 1 && tcp->ack == 1) {
            // Validate the server's sequence and the acknowledgment number we expect.
            // We expect server seq = 400, and ack_seq = (client_seq + 1) = 201.
            if (ntohl(tcp->seq) == 400 && ntohl(tcp->ack_seq) == 201) {
                std::cout << "[+] Received SYN-ACK from server "
                          << inet_ntoa(source_addr.sin_addr)
                          << " (seq=400, ack=201)" << std::endl;
                return true;
            }
        }
    }
    // In principle, we never hit this return in a normal flow; returning false as a fail-safe.
    return false;
}

// Constructs and sends the final ACK packet to complete the handshake.
// This ACK uses a sequence number of 600 and acknowledges the server's 400 by sending ack_seq=401.
void send_ack(int sock, struct sockaddr_in &server_addr) {
    // Packet again consists of IP header + TCP header.
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // IP header at the start of the packet.
    struct iphdr *ip = (struct iphdr*)packet;
    // TCP header follows immediately after the IP header.
    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));

    // Fill in the IP header.
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(54322);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = server_addr.sin_addr.s_addr;

    // Fill in the TCP header.
    tcp->source = htons(CLIENT_PORT);
    tcp->dest = server_addr.sin_port;
    tcp->seq = htonl(600);     // Final ACK packet sequence number.
    tcp->ack_seq = htonl(401); // Acknowledge the server’s sequence (400 + 1).
    tcp->doff = 5;
    tcp->syn = 0;
    tcp->ack = 1;              // ACK flag set.
    tcp->fin = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->window = htons(8192);
    tcp->check = 0;            // Checksum is left to 0 for simplicity.

    // Send the ACK packet back to the server.
    if (sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr*)(&server_addr), sizeof(server_addr)) < 0) {
        perror("sendto() failed for ACK");
        exit(EXIT_FAILURE);
    } else {
        std::cout << "[+] Sent ACK (seq=600, ack=401) -> Handshake complete." << std::endl;
    }
}

int main() {
    // Create a raw socket. This typically requires root/administrative privileges.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Enable IP_HDRINCL to allow manual control over IP header fields in the raw socket.
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    // Prepare the server address structure.
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);           // Server’s listening port.
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server’s IP address.

    // Phase 1: Send the SYN packet to initiate the handshake.
    send_syn(sock, server_addr);

    // Phase 2: Wait for the SYN-ACK packet from the server.
    if (receive_syn_ack(sock)) {
        // Phase 3: If we get the expected SYN-ACK, send the final ACK.
        send_ack(sock, server_addr);
    } else {
        std::cerr << "[-] Failed to receive valid SYN-ACK from server." << std::endl;
    }

    close(sock);
    return 0;
}
