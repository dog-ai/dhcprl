//
// Created by Hugo Freire on 2017-08-23.
//

#ifndef DHCPRL_DHCP_H
#define DHCPRL_DHCP_H

#include <sys/queue.h>

struct dhcp_request {
    LIST_ENTRY(dhcp_request) requests;
    time_t timestamp;
    char mac_address[40];
    char hostname[64];
};

LIST_HEAD(dhcp_request_list, dhcp_request) dhcp_requests;

void remove_older_dhcp_requests(int ttl);

int write_dhcp_request(int sock_fd, struct dhcp_request *dhcp_request);

int open_udp_broadcast_socket(int port);

void process_udp_broadcast_request(int sock_fd);

#endif //DHCPRL_DHCP_H
