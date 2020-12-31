#include "iodine-src/client.h"
#include "iodine-src/tun.h"
#include "client.h"
#include <cstddef>
#include <ctime>
#include <cstdio>
#include <netdb.h>
#include <cstdlib>
#include <cstring>

#define is_sending() (vars.outpkt.len != 0)

IodineClient::IodineClient() {
	client_init(&vars);
}

IodineClient::~IodineClient() {
	stop();
	// close_dns(vars.dns_fd);
}

void IodineClient::stop() {
	client_stop();
}

void IodineClient::set_nameserver(char *nameserv_host, int nameserv_family) {
	int nameservaddr_len = get_addr(nameserv_host, DNS_PORT, nameserv_family, 0, &nameservaddr);
	if (nameservaddr_len < 0) {
		errx(1, "Cannot lookup nameserver '%s': %s ",
			nameserv_host, gai_strerror(nameservaddr_len));
	}
	client_set_nameserver(&nameservaddr, nameservaddr_len);
}

void IodineClient::set_topdomain(const char *cp) {
	client_set_topdomain(cp);
}

void IodineClient::set_password(const char *cp) {
	client_set_password(cp);
}

int IodineClient::set_qtype(const char *qtype) {
	return client_set_qtype(qtype);
}

const char * IodineClient::get_qtype() {
	return client_get_qtype();
}

void IodineClient::set_downenc(char *encoding) {
	client_set_downenc(encoding);
}

void IodineClient::set_selecttimeout(int select_timeout) {
	client_set_selecttimeout(select_timeout);
}

void IodineClient::set_lazymode(int lazy_mode) {
	client_set_lazymode(lazy_mode);
}

void IodineClient::set_hostname_maxlen(int i) {
	client_set_hostname_maxlen(i);
}

void IodineClient::set_if_name(const char *if_name) {
	strncpy(vars.if_name, if_name, sizeof(vars.if_name));
	iodine_set_if_name(if_name);
}

const char * IodineClient::get_raw_addr() {
	return client_get_raw_addr();
}

int IodineClient::tunnel(int tun_fd) {
	printf("info: IodineClient: tunneling\n");
	int i;

	vars.lastdownstreamtime = time(NULL);
	vars.send_query_sendcnt = 0;  /* start counting now */

	while (vars.running) {
		struct timeval tv;
		tv.tv_sec = vars.selecttimeout;
		tv.tv_usec = 0;

		if (is_sending()) {
			/* fast timeout for retransmits */
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		}

		if (vars.send_ping_soon) {
			tv.tv_sec = 0;
			tv.tv_usec = vars.send_ping_soon * 1000;
		}

		fd_set fds;
		FD_ZERO(&fds);
		if (!is_sending() || vars.outchunkresent >= 2) {
			/* If re-sending upstream data, chances are that
			   we're several seconds behind already and TCP
			   will start filling tun buffer with (useless)
			   retransmits.
			   Get up-to-date fast by simply dropping stuff,
			   that's what TCP is designed to handle. */
			FD_SET(tun_fd, &fds);
		}
		FD_SET(dns_fd, &fds);

		i = select(MAX(tun_fd, dns_fd) + 1, &fds, NULL, NULL, &tv);

 		if (vars.lastdownstreamtime + 60 < time(NULL)) {
 			warnx("No downstream data received in 60 seconds, shutting down.");
 			vars.running = 0;
 		}

		if (vars.running == 0)
			break;

		if (i < 0)
			err(1, "select");

		if (i == 0) {
			printf("debug: IodineClient: select() timeout\n");
			/* timeout */
			if (is_sending()) {
				/* Re-send current fragment; either frag
				   or ack probably dropped somewhere.
				   But problem: no cache-miss-counter,
				   so hostname will be identical.
				   Just drop whole packet after 3 retries,
				   and TCP retransmit will solve it.
				   NOTE: tun dropping above should be
				   >=(value_here - 1) */
				if (vars.outchunkresent < 3) {
					vars.outchunkresent++;
					printf("debug: IodineClient: resending, outchunkresent=%d\n", vars.outchunkresent);
					send_chunk(dns_fd);
				} else {
					printf("debug: IodineClient: dropping packet, sending ping\n");
					vars.outpkt.offset = 0;
					vars.outpkt.len = 0;
					vars.outpkt.sentlen = 0;
					vars.outchunkresent = 0;

					send_ping(dns_fd);
				}
			} else {
				send_ping(dns_fd);
			}
			vars.send_ping_soon = 0;

		} else {

			if (FD_ISSET(tun_fd, &fds)) {
				printf("debug: IodineClient: tunnel_tun\n");
				if (tunnel_tun(tun_fd, dns_fd) <= 0)
					continue;
				/* Returns -1 on error OR when quickly
				   dropping data in case of DNS congestion;
				   we need to _not_ do tunnel_dns() then.
				   If chunk sent, sets vars.send_ping_soon=0. */
			}
			if (FD_ISSET(dns_fd, &fds)) {
				printf("debug: IodineClient: tunnel_dns\n");
				if (tunnel_dns(tun_fd, dns_fd) <= 0)
					continue;
			}
		}
	}

	return 0;
}

int IodineClient::handshake(char *if_name, int raw_mode, int autodetect_frag_size, int fragsize) {
	dns_fd = open_dns_from_host(NULL, 0, nameservaddr.ss_family, AI_PASSIVE);
	printf("debug: IodineClient: handshake begin\n");
	int ret = client_handshake(dns_fd, raw_mode, autodetect_frag_size, fragsize);
	printf("info: IodineClient: handshake end, status=%d\n", ret);
	return ret;
}

enum connection IodineClient::get_conn() { return client_get_conn(); }