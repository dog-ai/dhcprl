/*
 * Copyright (c) 2017, Hugo Freire <hugo@dog.ai>.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "dhcp.h"

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
    while ((j < data_len) && ((unsigned char) data[j] != 255)) {
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

void add_dhcp_request(time_t timestamp, char *mac_address, char *hostname) {
    struct dhcp_request *request;

    if (!(request = malloc(sizeof(struct dhcp_request)))) {
        errx(1, "malloc() failed");
    }

    request->timestamp = timestamp;
    strncpy(request->mac_address, mac_address, 40);
    strncpy(request->hostname, hostname, 64);

    LIST_INSERT_HEAD(&dhcp_requests, request, requests);
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

void remove_dhcp_request(char *mac_address, char *hostname) {
    struct dhcp_request *request;

    LIST_FOREACH(request, &dhcp_requests, requests) {
        if (strcmp(request->mac_address, mac_address) == 0 && strcmp(request->hostname, hostname) == 0) {
            LIST_REMOVE(request, requests);
            return;
        }
    }
}

void print_dhcp_request(struct dhcp_request *request) {
    printf("%lld %s %s\n", (long long) request->timestamp, request->mac_address, request->hostname);

    fflush(stdout);
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

    sprintf(buf, "%lld;%s;%s\n", (long long) dhcp_request->timestamp, dhcp_request->mac_address,
            dhcp_request->hostname);

    return write_all(sock_fd, buf, (int) strlen(buf));
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

void process_udp_broadcast_request(int sock_fd) {
    struct sockaddr_storage addr;
    char buf[10000];
    socklen_t fromlen = sizeof(addr);
    int n;

    if ((n = recvfrom(sock_fd, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &fromlen)) < 0) {
        errx(1, "recvfrom() failed");
    }

    time_t timestamp;             // timestamp on header
    char mac_address[40] = {0}; // mac address of origin
    char hostname[64] = {0};    // hostname

    timestamp = time(NULL);

    get_chaddr(mac_address, buf, n);

    if (strlen(mac_address) == 0) {
        return;
    }

    get_hostname(hostname, buf, n);

    add_or_update_dhcp_request(timestamp, mac_address, hostname);
}