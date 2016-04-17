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
#include <pcap.h>
#include <err.h>

#define SET_MAX(max, x)	if((x) > (max)) (max) = (x)

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

char errbuf[PCAP_ERRBUF_SIZE];

void process_socket_request(struct cli_request *cli_request);
int open_unix_socket(const char * path);
pcap_t *capture_packets(char *interface, char *filter);
void pcap_callback(char *user, const struct pcap_pkthdr *h, const char *sp);
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

	pcap_t *cap;

	int cap_fd, sock_srv_fd;
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

	cap = capture_packets(interface, "broadcast and udp dst port bootps");
	
	sock_srv_fd = open_unix_socket(sock_path);

	if ((cap_fd = pcap_get_selectable_fd(cap)) < 0) {
	    errx(1, "pcap_get_selectable_fd(): %s", pcap_geterr(cap));
	}

	LIST_INIT(&cli_requests);
	LIST_INIT(&dhcp_requests);

	while (1) {
        FD_ZERO(&rset);

    	FD_SET(cap_fd, &rset);
    	SET_MAX(max_fd, cap_fd);

    	FD_SET(sock_srv_fd, &rset);
    	SET_MAX(max_fd, sock_srv_fd);

    	struct cli_request *cli_request;

    	LIST_FOREACH(cli_request, &cli_requests, requests) {
			if(cli_request->sock_fd >= 0) {
				FD_SET(cli_request->sock_fd, &rset);
				SET_MAX(max_fd, cli_request->sock_fd);
			}
    	}

        if (select(max_fd + 1, &rset, 0, 0, 0) < 0) {
		    errx(1,"select() failed");
		}

		if (FD_ISSET(cap_fd, &rset)) {
			if (pcap_dispatch(cap, 0, (pcap_handler) pcap_callback, NULL) < 0) {
				errx(1,"pcap_loop(%s): %s", interface, pcap_geterr(cap));
			}
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
		if(FD_ISSET(sock_srv_fd, &rset)) {
		    struct cli_request *new_cli_request;
			int sock_cli_fd;;

			if((sock_cli_fd = accept(sock_srv_fd, NULL, NULL)) < 0) {
				warnx("accept() failed");
			} else {

				int flags;

				if((flags = fcntl(sock_cli_fd, F_GETFL)) < 0 || fcntl(sock_cli_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            		errx(1, "fcntl() failed");
            	}

				if(!(new_cli_request = malloc(sizeof(struct cli_request)))) {
					close(sock_srv_fd);
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

    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    return n==-1?-1:0; // return -1 on failure, 0 on success
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
            if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
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
	int sock_srv_fd;

	if((sock_srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    errx(1,"socket() failed");
	}

	/* unlink the socket pseudo file before binding */
	if(unlink(path) < 0 && errno != ENOENT) {
		close(sock_srv_fd);
		errx(1,"unlink() failed");
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	if(bind(sock_srv_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) < 0) {
		close(sock_srv_fd);
	}

	if(listen(sock_srv_fd, 5) < 0) {
		close(sock_srv_fd);
		errx(1,"listen() failed");
	}

	/* change socket permissions so everyone can communicate with us */
	if(chmod(path, 0666) < 0) {
		errx(1,"chmod() failed");
	}

	return sock_srv_fd;
}

pcap_t *capture_packets(char *interface, char *filter) {
	pcap_t *cap;
	struct bpf_program fp;

    if ((cap = pcap_open_live(interface, 1500, 1, 100, errbuf)) == NULL) {
		errx(1, "pcap_open_live(): %s", errbuf);
	}

	if (pcap_setnonblock(cap, 1, errbuf) < 0) {
	    errx(1, "pcap_setnonblock(): %s", pcap_geterr(cap));
	}

	if (pcap_compile(cap, &fp, filter, 0, 0) < 0) {
		errx(1,"pcap_compile: %s", pcap_geterr(cap));
	}

	if (pcap_setfilter(cap, &fp) < 0) {
		errx(1,"pcap_setfilter: %s", pcap_geterr(cap));
	}

	return cap;
}

void pcap_callback(char *user, const struct pcap_pkthdr *h, const char *sp) {
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;
	int offset = 0;
	time_t timestamp;			// timestamp on header
	char mac_address[40];			// mac address of origin
    char hostname[64];            // hostname

    memset(mac_address, '\0', sizeof(mac_address));
    memset(hostname, '\0', sizeof(hostname));

	if (h->caplen < ETHER_HDR_LEN) {
		printf("Ignored too short ethernet packet: %d bytes\n",
		    h->caplen);
		return;
	}

	eh = (struct ether_header *)(sp + offset);
	offset += ETHER_HDR_LEN;

	// Check for IPv4 packets
	if (eh->ether_type != 8) {
		printf("Ignored non IPv4 packet: %d\n", eh->ether_type);
		return;
	}

	// Check for length
	if (h->caplen < offset + sizeof(struct ip)) {
		printf("Ignored too short IPv4 packet: %d bytes\n", h->caplen);
		return;
	}

	ip = (struct ip *)(sp + offset);
	offset += sizeof(struct ip);

	udp = (struct udphdr *)(sp + offset);
	offset += sizeof(struct udphdr);


	timestamp = time(NULL);

	strcpy(mac_address, ether_ntoa_z((struct ether_addr *)eh->ether_shost));

	get_hostname(hostname, (char *)(sp + offset), ntohs(udp->uh_ulen));

	if (strlen(hostname) == 0) {
	    return;
	}

	add_or_update_dhcp_request(timestamp, mac_address, hostname);
}

void get_hostname(char *hostname, char *data, int data_len) {
	int	j;

	if (data_len == 0)
		return;

	j = 236;
	j += 4;	/* cookie */
	while (j < data_len && (int) data[j] != 255) {

        switch (data[j]) {
            case 12:	// Hostname
                strncpy(hostname, &data[j + 2], data[j + 1]);
                hostname[(int) data[j + 1]] = 0;
                return;

            default:

                break;
        }

        if (data[j]==0)		// padding
            j++;
        else
            j+=data[j + 1] + 2;

	}

	return;
}

void add_or_update_dhcp_request(time_t timestamp, char *mac_address, char *hostname) {
	struct dhcp_request *request;

    LIST_FOREACH(request, &dhcp_requests, requests) {
		if(strcmp(request->mac_address, mac_address) == 0 && strcmp(request->hostname, hostname) == 0) {
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
		if(now - request->timestamp > ttl) {
			LIST_REMOVE(request, requests);
			return;
		}
	}
}

void add_dhcp_request(time_t timestamp, char *mac_address, char *hostname) {
    struct dhcp_request *request;

    if(!(request = malloc(sizeof(struct dhcp_request)))) {
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
		if(strcmp(request->mac_address, mac_address) == 0 && strcmp(request->hostname, hostname) == 0) {
			LIST_REMOVE(request, requests);
			return;
		}
	}
}
