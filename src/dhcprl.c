/*
 * Copyright (c) 2016, Hugo Freire <hugo@exec.sh>.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/un.h> // unix sockets
#include <errno.h>
#include <unistd.h> // unlink() and close()
#include <sys/stat.h> // chmod()
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <time.h>    // time()

#define SET_MAX(max, x) if((x) > (max)) (max) = (x)

struct cli_request {
  int sock_fd;
  LIST_ENTRY(cli_request) requests;
  unsigned char *output_buffer;
  int output_buffer_offset;
  int output_buffer_len;
};

LIST_HEAD(cli_request_list, cli_request) cli_requests;

struct dhcp_request {
  LIST_ENTRY(dhcp_request) requests;
  time_t timestamp;
  char mac_address[40];
  char hostname[64];
};

LIST_HEAD(dhcp_request_list, dhcp_request) dhcp_requests;

void get_chaddr(char *chaddr, char *data, int data_len);
void process_udp_broadcast_request(int sock_fd);
int open_udp_broadcast_socket(int port);
void process_socket_request(struct cli_request *cli_request);
int open_unix_socket(const char * path);
void get_hostname(char *hostname, char *data, int data_len);
void add_or_update_dhcp_request(time_t timestamp, char *mac_address, char *hostname);
void remove_older_dhcp_requests(int ttl);
void add_dhcp_request(time_t timestamp, char *mac_address, char *hostname);
void remove_dhcp_request(char *mac_address, char *hostname);

void print_dhcp_request(struct dhcp_request *request) {
  printf("%lld %s %s\n", (long long) request->timestamp, request->mac_address, request->hostname);

  fflush(stdout);
}

void print_usage() {
  printf("Usage: $0 <-i interface> <-s socket>\n");
}

int dhcp_requests_size() {
  struct dhcp_request *request;
  int len = 0;

  LIST_FOREACH(request, &dhcp_requests, requests) {
    len++;
    print_dhcp_request(request);
  }

  return len;
}

char *ether_ntoa_z(const struct ether_addr *addr) {
  static char buf[18];

  sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
          addr->ether_addr_octet[0], addr->ether_addr_octet[1],
          addr->ether_addr_octet[2], addr->ether_addr_octet[3],
          addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

  return buf;
}

int main(int argc, char **argv) {
  char *interface = NULL;
  char *sock_path = NULL;
  int sock_unix_fd, sock_udp_fd;
  int max_fd = 0;
  fd_set rset;
  int i;

  for (i = 1; i < argc; i++) {
    if (argv[i] == NULL || argv[i][0] != '-') break;
    switch (argv[i][1]) {
    case 's':
      sock_path = argv[++i];
      break;
    case 'i':
      interface = argv[++i];
      break;
    default:
      fprintf(stderr, "%s: %c: uknown option\n", argv[0], argv[i][1]);
      print_usage();

      exit(0);
    }
  }

  if (interface == NULL || sock_path == NULL) {
    print_usage();
    exit(0);
  }

  sock_unix_fd = open_unix_socket(sock_path);
  sock_udp_fd = open_udp_broadcast_socket(67);

  LIST_INIT(&cli_requests);
  LIST_INIT(&dhcp_requests);

  while (1) {
    FD_ZERO(&rset);

    FD_SET(sock_unix_fd, &rset);
    SET_MAX(max_fd, sock_unix_fd);

    FD_SET(sock_udp_fd, &rset);
    SET_MAX(max_fd, sock_udp_fd);

    struct cli_request *cli_request;

    LIST_FOREACH(cli_request, &cli_requests, requests) {
      if (cli_request->sock_fd >= 0) {
        FD_SET(cli_request->sock_fd, &rset);
        SET_MAX(max_fd, cli_request->sock_fd);
      }
    }

    if (select(max_fd + 1, &rset, 0, 0, 0) < 0) {
      errx(1, "select() failed");
    }

    if (FD_ISSET(sock_udp_fd, &rset)) {
      process_udp_broadcast_request(sock_udp_fd);
    }

    remove_older_dhcp_requests(90);

    // handle existing unix socket requests
    LIST_FOREACH(cli_request, &cli_requests, requests) {
      if (cli_request->sock_fd >= 0 && FD_ISSET(cli_request->sock_fd, &rset)) {
        process_socket_request(cli_request);
      }

      // clean closed unix client sockets
      if (cli_request->sock_fd < 0) {
        LIST_REMOVE(cli_request, requests);
      }
    }

    // handle *new* unix socket requests
    if (FD_ISSET(sock_unix_fd, &rset)) {
      struct cli_request *new_cli_request;
      int sock_cli_fd;;

      if ((sock_cli_fd = accept(sock_unix_fd, NULL, NULL)) < 0) {
        warnx("accept() failed");
      } else {

        int flags;

        if ((flags = fcntl(sock_cli_fd, F_GETFL)) < 0 || fcntl(sock_cli_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
          errx(1, "fcntl() failed");
        }

        if (!(new_cli_request = malloc(sizeof(struct cli_request)))) {
          close(sock_unix_fd);
          errx(1, ("malloc() failed"));
        }

        memset(new_cli_request, 0, sizeof(struct cli_request));
        new_cli_request->sock_fd = sock_cli_fd;
        LIST_INSERT_HEAD(&cli_requests, new_cli_request, requests);
      }
    }
  }

  return 0;
}

int write_all(int s, char *buf, int len) {
  int total = 0;        // how many bytes we've sent
  int bytesleft = len; // how many we have left to send
  int n;

  while (total < len) {
    n = send(s, buf + total, bytesleft, 0);
    if (n == -1) { break; }
    total += n;
    bytesleft -= n;
  }

  return n == -1 ? -1 : 0; // return -1 on failure, 0 on success
}

int write_dhcp_request(int sock_fd, struct dhcp_request *dhcp_request) {
  char buf[117]; // 10 + ';' + 40 + ';' + 64 + '\n'

  sprintf(buf, "%lld;%s;%s\n", (long long) dhcp_request->timestamp, dhcp_request->mac_address, dhcp_request->hostname);

  return write_all(sock_fd, buf, (int) strlen(buf));
}

void process_socket_request(struct cli_request *cli_request) {
  ssize_t rbytes;
  unsigned char rbuf[1];

  do {

    rbytes = read(cli_request->sock_fd, rbuf, sizeof(rbuf));
    if (rbytes < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
    } else if (rbytes == 0) {
      break;
    }

  } while (1);

  struct dhcp_request *dhcp_request;

  LIST_FOREACH(dhcp_request, &dhcp_requests, requests) {
    write_dhcp_request(cli_request->sock_fd, dhcp_request);
  }

  close(cli_request->sock_fd);
  cli_request->sock_fd = -1;
}

int open_unix_socket(const char * path) {
  struct sockaddr_un addr;
  int sock_unix_fd;

  if ((sock_unix_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    errx(1, "socket() failed");
  }

  /* unlink the socket pseudo file before binding */
  if (unlink(path) < 0 && errno != ENOENT) {
    close(sock_unix_fd);
    errx(1, "unlink() failed");
  }

  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path));

  if (bind(sock_unix_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) < 0) {
    close(sock_unix_fd);
  }

  if (listen(sock_unix_fd, 5) < 0) {
    close(sock_unix_fd);
    errx(1, "listen() failed");
  }

  /* change socket permissions so everyone can communicate with us */
  if (chmod(path, 0666) < 0) {
    errx(1, "chmod() failed");
  }

  return sock_unix_fd;
}

void process_udp_broadcast_request(int sock_fd) {
  struct sockaddr_storage addr;
  char buf[10000];
  socklen_t fromlen = sizeof(addr);
  int n;

  if ((n = recvfrom(sock_fd, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &fromlen)) < 0) {
    errx(1, "recvfrom() failed");
  }

  time_t timestamp;           // timestamp on header
  char mac_address[40];       // mac address of origin
  char hostname[64];          // hostname

  timestamp = time(NULL);

  get_chaddr(mac_address, buf, n);

  if (strlen(mac_address) == 0) {
    return;
  }

  get_hostname(hostname, buf, n);

  if (strlen(hostname) == 0) {
    return;
  }

  add_or_update_dhcp_request(timestamp, mac_address, hostname);
}

int open_udp_broadcast_socket(int port) {
  struct sockaddr_in addr;
  int sock_fd;

  if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    errx(1, "socket() failed");
  }

  int broadcast = 1;

  if (setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) < 0) {
    errx(1, "setsockopt() failed");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr)) < 0) {
    errx(1, "bind() failed");
  }

  return sock_fd;
}

void get_chaddr(char *chaddr, char *data, int data_len) {
  if (data_len < 43) return;

  sprintf(chaddr,
          "%02x:%02x:%02x:%02x:%02x:%02x",
          (unsigned char) data[28], (unsigned char) data[29], (unsigned char) data[30],
          (unsigned char) data[31], (unsigned char) data[32], (unsigned char) data[33]);
}

void get_hostname(char *hostname, char *data, int data_len) {
  int j;

  if (data_len == 0) {
    return;
  }

  j = 236;
  j += 4; /* cookie */
  while (j < data_len && (int) data[j] != 255) {

    switch (data[j]) {
    case 12:  // Hostname
      strncpy(hostname, &data[j + 2], data[j + 1]);
      hostname[(int) data[j + 1]] = 0;
      return;

    default:

      break;
    }

    if (data[j] == 0) // padding
      j++;
    else
      j += data[j + 1] + 2;

  }

  return;
}

void add_or_update_dhcp_request(time_t timestamp, char *mac_address, char *hostname) {
  struct dhcp_request *request;

  LIST_FOREACH(request, &dhcp_requests, requests) {
    if (strcmp(request->mac_address, mac_address) == 0 && strcmp(request->hostname, hostname) == 0) {
      request->timestamp = timestamp;
      return;
    }
  }

  return add_dhcp_request(timestamp, mac_address, hostname);
}

void remove_older_dhcp_requests(int ttl) {
  struct dhcp_request *request;
  time_t now = time(NULL);

  LIST_FOREACH(request, &dhcp_requests, requests) {
    if (now - request->timestamp > ttl) {
      LIST_REMOVE(request, requests);
      return;
    }
  }
}

void add_dhcp_request(time_t timestamp, char *mac_address, char *hostname) {
  struct dhcp_request *request;

  if (!(request = malloc(sizeof(struct dhcp_request)))) {
    errx(1, "malloc() failed");
  }

  request->timestamp = timestamp;
  strcpy(request->mac_address, mac_address);
  strcpy(request->hostname, hostname);

  LIST_INSERT_HEAD(&dhcp_requests, request, requests);
}

void remove_dhcp_request(char *mac_address, char *hostname) {
  struct dhcp_request *request;

  LIST_FOREACH(request, &dhcp_requests, requests) {
    if (strcmp(request->mac_address, mac_address) == 0 && strcmp(request->hostname, hostname) == 0) {
      LIST_REMOVE(request, requests);
      return;
    }
  }
}
