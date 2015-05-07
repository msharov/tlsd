// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#pragma once
#include <casycom.h>

#ifdef __cplusplus
extern "C" {
#endif

//----------------------------------------------------------------------

typedef void (*MFN_TLSTunnel_Open)(void* o, const char* host, const char* port);
typedef struct _DTLSTunnel {
    const Interface*	interface;
    MFN_TLSTunnel_Open	TLSTunnel_Open;
} DTLSTunnel;

void PTLSTunnel_Open (const Proxy* pp, const char* host, const char* port) noexcept;

extern const Interface i_TLSTunnel;

//----------------------------------------------------------------------

typedef void (*MFN_TLSTunnelR_Connected)(void* o, int sfd);
typedef struct _DTLSTunnelR {
    const Interface*		interface;
    MFN_TLSTunnelR_Connected	TLSTunnelR_Connected;
} DTLSTunnelR;

void PTLSTunnelR_Connected (const Proxy* pp, int sfd) noexcept;

extern const Interface i_TLSTunnelR;

//----------------------------------------------------------------------

#ifdef __cplusplus
} // extern "C"
#endif
