/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for lwIP's sockets.h: the host's BSD socket API has
 * the setsockopt / IPPROTO_TCP / TCP_NODELAY that ts2021_client.c uses. */
#pragma once

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
