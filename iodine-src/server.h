#pragma once

#include "common.h"

extfun int get_external_ip(struct in_addr *ip);
extfun int server_tunnel(int tun_fd, int dns_fd, int bind_fd, int max_idle_time);
extfun void set_vars(struct iodine_server_vars *src);
extfun void init_encoders();