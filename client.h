#pragma once

#include "../client.h"
#include "iodine-src/common.h"

class IodineClient : public Client {
	struct iodine_client_vars vars;
	struct sockaddr_storage nameservaddr;
	int dns_fd;

	int is_sending();

public:
	IodineClient();
	~IodineClient();

	void stop();

	void set_nameserver(char *nameserv_host, int nameserv_family);
	void set_topdomain(const char *cp);
	void set_password(const char *cp);
	int set_qtype(const char *qtype);
	const char * get_qtype();
	void set_downenc(char *encoding);
	void set_selecttimeout(int select_timeout);
	void set_lazymode(int lazy_mode);
	void set_if_name(const char*);
	void set_hostname_maxlen(int i);
	const char * get_raw_addr();
	enum connection get_conn();

	int tunnel(int tun_fd);
	int handshake(char *if_name, int raw_mode, int autodetect_frag_size, int fragsize);
};