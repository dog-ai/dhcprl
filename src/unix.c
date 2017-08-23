/*
 * Copyright (c) 2016, Hugo Freire <hugo@dog.ai>.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h> // unix sockets
#include <errno.h>
#include <unistd.h> // unlink() and close()
#include <sys/stat.h> // chmod()
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include "unix.h"

#include "dhcp.h"

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

int open_unix_socket(const char *path) {
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
