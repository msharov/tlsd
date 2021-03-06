// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#pragma once
#include <casycom.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLSD_SOCKET	"tlsd.socket"

//----------------------------------------------------------------------

typedef void (*MFN_TLSTunnel_open)(void* o, const char* host, const char* port);
typedef struct _DTLSTunnel {
    const Interface*	interface;
    MFN_TLSTunnel_open	TLSTunnel_open;
} DTLSTunnel;

void PTLSTunnel_open (const Proxy* pp, const char* host, const char* port) noexcept;

extern const Interface i_TLSTunnel;

//----------------------------------------------------------------------

typedef void (*MFN_TLSTunnelR_connected)(void* o, int sfd);
typedef struct _DTLSTunnelR {
    const Interface*		interface;
    MFN_TLSTunnelR_connected	TLSTunnelR_connected;
} DTLSTunnelR;

void PTLSTunnelR_connected (const Proxy* pp, int sfd) noexcept;

extern const Interface i_TLSTunnelR;

//----------------------------------------------------------------------

#ifdef __cplusplus
} // extern "C"
#endif
