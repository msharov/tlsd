// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#include "libtlsd.h"

//{{{ TLSTunnel interface ----------------------------------------------

enum { method_TLSTunnel_open };

void PTLSTunnel_open (const Proxy* pp, const char* host, const char* port)
{
    Msg* msg = casymsg_begin (pp, method_TLSTunnel_open, casystm_size_string(host)+casystm_size_string(port));
    WStm os = casymsg_write (msg);
    casystm_write_string (&os, host);
    casystm_write_string (&os, port);
    casymsg_end (msg);
}

static void TLSTunnel_dispatch (const DTLSTunnel* dtable, void* o, const Msg* msg)
{
    if (msg->imethod == method_TLSTunnel_open) {
	RStm is = casymsg_read (msg);
	const char* host = casystm_read_string (&is);
	const char* port = casystm_read_string (&is);
	dtable->TLSTunnel_open (o, host, port);
    } else
	casymsg_default_dispatch (dtable, o, msg);
}

const Interface i_TLSTunnel = {
    .name       = "TLSTunnel",
    .dispatch   = TLSTunnel_dispatch,
    .method     = { "Open\0ss", NULL }
};

//}}}-------------------------------------------------------------------
//{{{ TLSTunnelR interface

enum { method_TLSTunnelR_connected };

void PTLSTunnelR_connected (const Proxy* pp, int sfd)
{
    Msg* msg = casymsg_begin (pp, method_TLSTunnelR_connected, 4);
    WStm os = casymsg_write (msg);
    casymsg_write_fd (msg, &os, sfd);
    casymsg_end (msg);
}

static void TLSTunnelR_dispatch (const DTLSTunnelR* dtable, void* o, const Msg* msg)
{
    if (msg->imethod == method_TLSTunnelR_connected) {
	RStm is = casymsg_read (msg);
	int sfd = casymsg_read_fd (msg, &is);
	dtable->TLSTunnelR_connected (o, sfd);
    } else
	casymsg_default_dispatch (dtable, o, msg);
}

const Interface i_TLSTunnelR = {
    .name       = "TLSTunnelR",
    .dispatch   = TLSTunnelR_dispatch,
    .method     = { "Connected\0h", NULL }
};

//}}}-------------------------------------------------------------------
