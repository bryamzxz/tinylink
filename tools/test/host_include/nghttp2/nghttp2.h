/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in: ts2021_client.h names the nghttp2 session type in
 * ts2021_conn_t; test_ts2021.c never touches it. */
#pragma once

typedef struct nghttp2_session nghttp2_session;
