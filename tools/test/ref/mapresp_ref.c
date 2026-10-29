// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The whole-body MapResponse parser (mapresp_133.c) under ref_* names, so a
// test can link it next to the current mapreq.c.

#define mapresp_parse   ref_mapresp_parse
#define tl_netmap_clear ref_tl_netmap_clear
#include "mapresp_133.c"
