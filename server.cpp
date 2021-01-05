#include "server.h"
#include "../../tun.h"
#include "iodine-src/common.h"
#include "iodine-src/fw_query.h"
#include "iodine-src/server.h"
#include "iodine-src/user.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>

#ifdef WINDOWS32
#include "windows.h"
#include <winsock2.h>
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#define _XPG4_2
#include <netdb.h>
#endif

#define PASSWORD_ENV_VAR "IODINED_PASS"

IodineServer::IodineServer() {
	srand(time(NULL));
	fw_query_init();
}

IodineServer::~IodineServer() {
	close(dnsd_fd);
	close(tun_fd);
}

void IodineServer::stop() {}

#define warnx(...) { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); }
#define usage() { fprintf(stderr, "Use -h for usage info.\n"); return 1; } // todo: fix

int IodineServer::init(struct iodine_server_config config) {
	char *netsize;
	vars.netmask = 27;
	if ((config.ip_string != nullptr) && (netsize = strchr(config.ip_string, '/'))) {
		*netsize = 0;
		netsize++;
		vars.netmask = atoi(netsize);
	}

	vars.my_ip = inet_addr(config.ip_string);

	vars.ns_ip = config.ns_ip;
	if (config.ns_get_externalip) {
		struct in_addr extip;
		int res = get_external_ip(&extip);
		if (res) {
			fprintf(stderr, "Failed to get external IP via web service.\n");
			exit(3);
		}
		vars.ns_ip = extip.s_addr;
		fprintf(stderr, "Using %s as external IP.\n", inet_ntoa(extip));
	}

	if (vars.my_ip == INADDR_NONE) {
		warnx("Bad IP address to use inside tunnel.");
		usage();
	}

	vars.topdomain = strdup(config.topdomain);
	char *errormsg;
	if(check_topdomain(vars.topdomain, &errormsg)) {
		warnx("Invalid topdomain: %s", errormsg);
		usage();
		/* NOTREACHED */
	}

	if (config.mtu <= 0) {
		warnx("Bad MTU given.");
		usage();
	}

	if(config.port < 1 || config.port > 65535) {
		warnx("Bad port number given.");
		usage();
	}

	if (config.port != 53) {
		fprintf(stderr, "ALERT! Other dns servers expect you to run on port 53.\n");
		fprintf(stderr, "You must manually forward port 53 to port %d for things to work.\n", config.port);
	}

	struct sockaddr_storage dnsaddr;
	int dnsaddr_len = get_addr(config.listen_ip, config.port, AF_INET, AI_PASSIVE | AI_NUMERICHOST, &dnsaddr);
	if (dnsaddr_len < 0) {
		warnx("Bad IP address to listen on.");
		usage();
	}

	if(config.bind_enable) {
		in_addr_t dns_ip = ((struct sockaddr_in *) &dnsaddr)->sin_addr.s_addr;
		if (config.bind_port < 1 || config.bind_port > 65535) {
			warnx("Bad DNS server port number given.");
			usage();
			/* NOTREACHED */
		}
		/* Avoid forwarding loops */
		if (config.bind_port == config.port && (dns_ip == INADDR_ANY || dns_ip == htonl(0x7f000001L))) {
			warnx("Forward port is same as listen port (%d), will create a loop!", config.bind_port);
			fprintf(stderr, "Use -l to set listen ip to avoid this.\n");
			usage();
			/* NOTREACHED */
		}
		fprintf(stderr, "Requests for domains outside of %s will be forwarded to port %d\n",
			vars.topdomain, config.bind_port);
		vars.bind_port = config.bind_port;
	}

	if (vars.ns_ip == INADDR_NONE) {
		warnx("Bad IP address to return as nameserver.");
		usage();
	}
	if (vars.netmask > 30 || vars.netmask < 8) {
		warnx("Bad netmask (%d bits). Use 8-30 bits.", vars.netmask);
		usage();
	}

	if (strlen(config.password) == 0) {
		if (NULL != getenv(PASSWORD_ENV_VAR))
			snprintf(config.password, sizeof(config.password), "%s", getenv(PASSWORD_ENV_VAR));
		else
			read_password(config.password, sizeof(config.password));
	}
	strncpy(vars.password, config.password, sizeof(vars.password));

	vars.created_users = init_users(vars.my_ip, vars.netmask);

	char if_name[250];

	// todo: move to server.cpp
	if ((tun_fd = open_tun(if_name, config.device)) == -1) {
		return 1;
	}
	if (!config.skipipconfig) {
		const char *other_ip = users_get_first_ip();
		if (tun_setip(if_name, config.ip_string, other_ip, vars.netmask) != 0 || tun_setmtu(if_name, config.mtu) != 0) {
			close(tun_fd);
			free((void*) other_ip);
			return 1;
		}
		free((void*) other_ip);
	}
#ifdef HAVE_SYSTEMD
	nb_fds = sd_listen_fds(0);
	if (nb_fds > 1) {
		retval = 1;
		warnx("Too many file descriptors received!\n");
		goto cleanup1;
	} else if (nb_fds == 1) {
		dnsd_fd = SD_LISTEN_FDS_START;
	} else {
#endif
		if ((dnsd_fd = open_dns(&dnsaddr, dnsaddr_len)) < 0) {
			close(dnsd_fd);
			close(tun_fd);
			return 1;
		}
#ifdef HAVE_SYSTEMD
	}
#endif

	bind_fd = 0;
	if (config.bind_enable) {
		if ((bind_fd = open_dns_from_host(NULL, 0, AF_INET, 0)) < 0) {
			close(bind_fd);
			close(dnsd_fd);
			close(tun_fd);
			return 1;
		}
	}

	vars.my_mtu = config.mtu;
	vars.check_ip = config.check_ip;

	if (vars.created_users < USERS) {
		fprintf(stderr, "Limiting to %d simultaneous users because of netmask /%d\n",
			vars.created_users, vars.netmask);
	}
	fprintf(stderr, "Listening to dns for domain %s\n", vars.topdomain);
	set_vars(&vars);
	init_encoders();
	return 0;
}

int IodineServer::tunnel(/*int tun_fd, int dnsd_fd, */int max_idle_time) {
	return server_tunnel(tun_fd, dnsd_fd, bind_fd, max_idle_time);
}

void IodineServer::auto_external_ip() {
	struct in_addr extip;
	int res = get_external_ip(&extip);
	if (res) {
		fprintf(stderr, "Failed to get external IP via web service.\n");
		exit(3);
	}
	vars.ns_ip = extip.s_addr;
	fprintf(stderr, "Using %s as external IP.\n", inet_ntoa(extip));
}