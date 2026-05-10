// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "disco_replay.h"

#include <string.h>

static struct {
    uint8_t nonce[DISCO_NONCE_LEN];
    bool    valid;
} s_window[DISCO_REPLAY_WINDOW_SIZE];
static size_t s_next;

bool disco_replay_check_and_record(const uint8_t nonce[DISCO_NONCE_LEN])
{
    for (size_t i = 0; i < DISCO_REPLAY_WINDOW_SIZE; i++) {
        if (s_window[i].valid &&
            memcmp(s_window[i].nonce, nonce, DISCO_NONCE_LEN) == 0) {
            return true;
        }
    }
    memcpy(s_window[s_next].nonce, nonce, DISCO_NONCE_LEN);
    s_window[s_next].valid = true;
    s_next = (s_next + 1) % DISCO_REPLAY_WINDOW_SIZE;
    return false;
}

void disco_replay_reset(void)
{
    memset(s_window, 0, sizeof(s_window));
    s_next = 0;
}
