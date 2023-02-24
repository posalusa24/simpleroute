/*
 * ring - a ping implementation
 * 
 * USAGE
 *   ring <srcination-ip-address>
 *
 * DESCRIPTION
 *   ring sends an ICMP ECHO_REQUEST to a specified srcination address and
 *   waits (a specific amount of time before timing out) for an ICMP ECHO_REPLY.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

struct icmp_packet {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t seq_num;
  struct timeval timestamp;
};

struct ip_packet {
  char header[20];
  struct icmp_packet payload_icmp;
} __attribute__((packed));

unsigned short icmp_packet_calc_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
 
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    if (len == 1) {
        sum += *(unsigned char*) buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void icmp_packet_build_echo_req(struct icmp_packet *packet, uint16_t identifier_host_byte_order, uint16_t seq_num_host_byte_order) {
  memset(packet, 0, sizeof(*packet));
  packet->type = 8;
  packet->code = 0;
  packet->identifier = htons(identifier_host_byte_order);
  packet->seq_num = htons(seq_num_host_byte_order);
  gettimeofday(&packet->timestamp, NULL);
  packet->timestamp.tv_sec = htonl(packet->timestamp.tv_sec);
  packet->timestamp.tv_usec = htonl(packet->timestamp.tv_usec);

  packet->checksum = icmp_packet_calc_checksum(packet, sizeof(*packet));
}

void print_icmp_packet(struct icmp_packet packet) {
  printf("Type: %d\n", packet.type);
  printf("Code: %d\n", packet.code);
  printf("Checksum: %d\n", ntohs(packet.checksum));
  printf("Identifier: %d\n", ntohs(packet.identifier));
  printf("Sequence No.: %d\n", ntohs(packet.seq_num));

  time_t tv_sec = ntohl(packet.timestamp.tv_sec);
  struct tm *tm = localtime(&tv_sec);
  char timestamp_str[64];
  strftime(timestamp_str, sizeof(timestamp_str), "%H:%M:%S", tm);
  printf("Timestamp: %s\n", timestamp_str);
}

int main(int argc, char **argv) {
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    fprintf(stderr, "sockfd error\n");
    return -1;
  }

  int ttl_val = 1;

  if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
    fprintf(stderr, "setsockopt error\n");
    return -1;
  }

  struct timeval tv_out;
  tv_out.tv_sec = 1;
  tv_out.tv_usec = 0;

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv_out, sizeof(tv_out));

  struct icmp_packet sent_packet;
  struct ip_packet received_packet;

  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  socklen_t dest_addr_len = sizeof(dest_addr);
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(argv[1]);

  struct sockaddr_in src_addr;
  memset(&src_addr, 0, sizeof(src_addr));
  socklen_t src_addr_len = sizeof(src_addr);

  for (int i = 0; i < 65536; i++) {
    icmp_packet_build_echo_req(&sent_packet, 12, 12);

    usleep(100000);

    if (sendto(sockfd, &sent_packet, sizeof(sent_packet), 0, (struct sockaddr *) &dest_addr, dest_addr_len) <= 0) {
      fprintf(stderr, "error\n");
      return -1;
    }

    memset(&received_packet, 0, sizeof(received_packet));

    int return_code;
    if (return_code = recvfrom(sockfd, &received_packet, sizeof(received_packet), 0, (struct sockaddr *) &src_addr, &src_addr_len) <= 0) {
      if (return_code == 1) {
        printf("%d. From: ***\n", ttl_val++);
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
          fprintf(stderr, "setsockopt error\n");
          return -1;
        }
        continue;
      }
      fprintf(stderr, "recvfrom error: %d\n", return_code);
      return -1;
    }

    printf("%d. From: %s\n", ttl_val++, inet_ntoa(src_addr.sin_addr));

    int reached = received_packet.payload_icmp.type == 0;
    if (reached) {
      printf("DONE\n");
      break;
    } else {
      if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        fprintf(stderr, "setsockopt error\n");
        return -1;
      }
    }
  }

  return 0;
}
