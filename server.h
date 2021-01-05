#pragma once

#include "../server.h"
#include "iodine-src/common.h"

struct iodine_server_config {
	int ns_get_externalip;
	in_addr_t ns_ip;
	// ip_string contains an ip and a subnet: "1.2.3.4/8"
	char *ip_string;
	const char *topdomain;
	int mtu;
	int port;
	char *listen_ip;
	int bind_enable;
	int bind_port;
	char password[33];
	char *device;
	int skipipconfig;
	int check_ip;
};

class IodineServer : public Server {
	struct iodine_server_vars vars;
	int tun_fd;
	int dnsd_fd;
	int bind_fd;

public:
	IodineServer();
	~IodineServer();

	void auto_external_ip();
	int tunnel(/*int tun_fd, int dnsd_fd, */int max_idle_time);

	int init(struct iodine_server_config config);
	void stop();
};