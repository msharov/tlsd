// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "../config.h"
#include "../libtlsd.h"

//----------------------------------------------------------------------

typedef struct {
    Proxy	connp;
    int		sfd;
    Proxy	sio;
    CharVector	rbuf;
    CharVector	wbuf;
    Proxy	externp;
    const char*	serverArg;
} App;

//----------------------------------------------------------------------

static void* App_Create (const Msg* msg UNUSED)
{
    static App app = {
	PROXY_INIT,
	-1,
	PROXY_INIT,
	VECTOR_INIT(CharVector),
	VECTOR_INIT(CharVector),
	PROXY_INIT,
	"-p"
    };
    return &app;
}
static void App_Destroy (void* o UNUSED) {}

static void App_App_Init (App* app, unsigned argc, char* const* argv)
{
    for (int opt; 0 < (opt = getopt (argc, argv, "dD"));) {
	if (opt == 'd')
	    casycom_enable_debug_output();
	else if (opt == 'D')
	    app->serverArg = "-pd";
	else {
	    printf ("Usage: tunnl [-dD]\n"
		    "  -d\tenable debug tracing\n"
		    "  -D\tenable server debug tracing\n");
	    exit (EXIT_SUCCESS);
	}
    }
    casycom_enable_externs();
    casycom_register (&f_FdIO);
    app->sio = casycom_create_proxy (&i_FdIO, oid_App);
    app->externp = casycom_create_proxy (&i_Extern, oid_App);
    static const iid_t iil[] = { &i_TLSTunnel, NULL };
    printf ("Launching %s %s\n", TLSD_NAME, app->serverArg);
    if (0 > PExtern_LaunchPipe (&app->externp, TLSD_NAME, app->serverArg, iil))
	return casycom_error ("PExtern_LaunchPipe: %s", strerror(errno));
}

static void App_ExternR_Connected (App* app, const ExternInfo* einfo)
{
    bool bHaveTunnel = false;
    printf ("Connected to server. Imported %zu interface:", einfo->interfaces.size);
    for (size_t i = 0; i < einfo->interfaces.size; ++i) {
	printf (" %s", einfo->interfaces.d[i]->name);
	if (einfo->interfaces.d[i] == &i_TLSTunnel)
	    bHaveTunnel = true;
    }
    printf ("\n");
    if (!bHaveTunnel)
	return casycom_error ("connected to server that does not support the TLSTunnel interface");
    app->connp = casycom_create_proxy (&i_TLSTunnel, oid_App);
    PTLSTunnel_Open (&app->connp, "192.168.1.1", "https");
}

static void App_IOR_Read (App* app, CharVector* d)
{
    if (!d)
	return casycom_quit (EXIT_SUCCESS);
    fflush (stdout);
    while (d->size) {
	const char* pdate = strstr (d->d, "Date: "), *pnl;
	if (pdate && ((pnl = strchr (pdate, '\n'))))
	    vector_erase_n (d, pdate - d->d, pnl-pdate+1);
	ssize_t bw = write (STDOUT_FILENO, d->d, d->size);
	if (bw <= 0) {
	    if (errno == EINTR)
		continue;
	    return casycom_error ("write: %s", strerror(errno));
	}
	vector_erase_n (d, 0, bw);
    }
    PIO_Read (&app->sio, d);
}

static void App_TLSTunnelR_Connected (App* app, int sfd)
{
    app->sfd = sfd;
    vector_reserve (&app->rbuf, 4096);
    vector_reserve (&app->wbuf, 4096);
    int bw = snprintf (app->wbuf.d, app->wbuf.allocated, "GET / HTTP/1.1\nHost: 192.168.1.1\n\n");
    if ((size_t) bw >= app->wbuf.allocated)
	return casycom_error ("snprintf: %s", strerror(errno));
    app->wbuf.size = bw;
    PFdIO_Attach (&app->sio, sfd);
    PIO_Read (&app->sio, &app->rbuf);
    PIO_Write (&app->sio, &app->wbuf);
}

//----------------------------------------------------------------------

static const DApp d_App_App = {
    .interface = &i_App,
    DMETHOD (App, App_Init)
};
static const DExternR d_App_ExternR = {
    .interface = &i_ExternR,
    DMETHOD (App, ExternR_Connected)
};
static const DTLSTunnelR d_App_TLSTunnelR = {
    .interface = &i_TLSTunnelR,
    DMETHOD (App, TLSTunnelR_Connected)
};
static const DIOR d_App_IOR = {
    .interface = &i_IOR,
    DMETHOD (App, IOR_Read)
};
static const Factory f_App = {
    .Create     = App_Create,
    .Destroy    = App_Destroy,
    .dtable     = { &d_App_App, &d_App_ExternR, &d_App_TLSTunnelR, &d_App_IOR, NULL }
};

CASYCOM_MAIN (f_App)
