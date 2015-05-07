// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "libtlsd.h"

//{{{ TLSTunnel interface ----------------------------------------------

enum { method_TLSTunnel_Open };

void PTLSTunnel_Open (const Proxy* pp, const char* host, const char* port, const char* prewrite)
{
    Msg* msg = casymsg_begin (pp, method_TLSTunnel_Open, casystm_size_string(host)+casystm_size_string(port)+casystm_size_string(prewrite));
    WStm os = casymsg_write (msg);
    casystm_write_string (&os, host);
    casystm_write_string (&os, port);
    casystm_write_string (&os, prewrite);
    casymsg_end (msg);
}

static void TLSTunnel_Dispatch (const DTLSTunnel* dtable, void* o, const Msg* msg)
{
    if (msg->imethod == method_TLSTunnel_Open) {
	RStm is = casymsg_read (msg);
	const char* host = casystm_read_string (&is);
	const char* port = casystm_read_string (&is);
	const char* prewrite = casystm_read_string (&is);
	dtable->TLSTunnel_Open (o, host, port, prewrite);
    } else
	casymsg_default_dispatch (dtable, o, msg);
}

const Interface i_TLSTunnel = {
    .name       = "TLSTunnel",
    .dispatch   = TLSTunnel_Dispatch,
    .method     = { "Open\0sss", NULL }
};

//}}}-------------------------------------------------------------------
//{{{ TLSTunnelR interface

enum { method_TLSTunnelR_Connected };

void PTLSTunnelR_Connected (const Proxy* pp, int sfd)
{
    Msg* msg = casymsg_begin (pp, method_TLSTunnelR_Connected, 4);
    WStm os = casymsg_write (msg);
    casymsg_write_fd (msg, &os, sfd);
    casymsg_end (msg);
}

static void TLSTunnelR_Dispatch (const DTLSTunnelR* dtable, void* o, const Msg* msg)
{
    if (msg->imethod == method_TLSTunnelR_Connected) {
	RStm is = casymsg_read (msg);
	int sfd = casymsg_read_fd (msg, &is);
	dtable->TLSTunnelR_Connected (o, sfd);
    } else
	casymsg_default_dispatch (dtable, o, msg);
}

const Interface i_TLSTunnelR = {
    .name       = "TLSTunnelR",
    .dispatch   = TLSTunnelR_Dispatch,
    .method     = { "Connected\0h", NULL }
};

//}}}-------------------------------------------------------------------
