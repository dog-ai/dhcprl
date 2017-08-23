/*
 * Copyright (c) 2017, Hugo Freire <hugo@dog.ai>.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <unistd.h> // unlink() and close()
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "../include/dhcprld.h"

#include "dhcp.h"
#include "unix.h"

void print_usage() {
  printf("Usage: dhcprld <-i interface> <-s socket>\n");
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
      case 's':sock_path = argv[++i];
        break;
      case 'i':interface = argv[++i];
        break;
      default:fprintf(stderr, "%s: %c: uknown option\n", argv[0], argv[i][1]);
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
