// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#include "../config.h"
#include "../libtlsd.h"

//----------------------------------------------------------------------
// Main application object

typedef struct {
    Proxy	connp;		// the encrypted connection requestor
    int		sfd;		// the proxy socket you get from tlsd
    Proxy	sio;		// asynchronous socket reader
    CharVector	wbuf;		//	sending this to server, and
    CharVector	rbuf;		//	receiving server responsed here
    Proxy	externp;	// casycom connection to tlsd
    const char*	server_arg;	// command line options to pass to tlsd, if launching
} App;

//----------------------------------------------------------------------

static void* App_create (const Msg* msg UNUSED)
{
    static App app = {
	PROXY_INIT,
	-1,
	PROXY_INIT,
	VECTOR_INIT(CharVector),
	VECTOR_INIT(CharVector),
	PROXY_INIT,
	"-p"	// if launching tlsd, create a private connection
    };
    return &app;
}
static void App_destroy (void* o UNUSED) {}

static void App_App_init (App* app, unsigned argc, char* const* argv)
{
    bool bTestSystemService = false;
    for (int opt; 0 < (opt = getopt (argc, argv, "sdD"));) {
	if (opt == 's')		// request connection to the system tlsd.socket
	    bTestSystemService = true;
	else if (opt == 'd')	// debug this client
	    casycom_enable_debug_output();
	else if (opt == 'D')	// debug tlsd itself
	    app->server_arg = "-pd";
	else {
	    printf ("Usage: tunnl [-dD]\n"
		    "  -d\tenable debug tracing\n"
		    "  -D\tenable server debug tracing\n");
	    exit (EXIT_SUCCESS);
	}
    }
    // Enable extern connections, to create remote objects in tlsd
    casycom_enable_externs();
    // Register the asynchronous socket IO object type
    casycom_register (&f_FdIO);
    // sio is the proxy for the socket reader
    app->sio = casycom_create_proxy (&i_FdIO, oid_App);
    // externp is the proxy for the remote object requestor
    app->externp = casycom_create_proxy (&i_Extern, oid_App);
    // Setup interface request list, containing the i_TLSTunnel interface
    static const iid_t iil[] = { &i_TLSTunnel, NULL };

    if (bTestSystemService) {
	printf ("Connecting to system tlsd\n");
        if (0 > PExtern_connect_system_local (&app->externp, TLSD_SOCKET, iil))
	    casycom_error ("Extern_connect_system_local: %s", strerror(errno));
    } else {
	printf ("Launching %s %s\n", TLSD_NAME, app->server_arg);
	if (0 > PExtern_launch_pipe (&app->externp, TLSD_NAME, app->server_arg, iil))
	    return casycom_error ("PExtern_launch_pipe: %s", strerror(errno));
    }
}

static void App_ExternR_connected (App* app, const ExternInfo* einfo)
{
    // tlsd connection established and it sent us the list of supported interfaces
    bool bHaveTunnel = false;
    // print them all for debugging purposes
    printf ("Connected to server. Imported %zu interface:", einfo->interfaces.size);
    for (size_t i = 0; i < einfo->interfaces.size; ++i) {
	printf (" %s", einfo->interfaces.d[i]->name);
	if (einfo->interfaces.d[i] == &i_TLSTunnel)
	    bHaveTunnel = true;
    }
    printf ("\n");
    if (!bHaveTunnel)
	return casycom_error ("connected to server that does not support the TLSTunnel interface");

    // Now that we know tlsd supports the i_TLSTunnel interface,
    // we can create a tunnel object there.
    app->connp = casycom_create_proxy (&i_TLSTunnel, oid_App);
    // With the tunnel object created, connect it to the web server (your router)
    PTLSTunnel_open (&app->connp, "192.168.1.1", "8443");
    // When the TLS connection has been established, connp will send
    // us a TLSTunnelR_connected message with a proxy file descriptor
}

static void App_TLSTunnelR_connected (App* app, int sfd)
{
    // sfd is the unencrypted proxy socket which tlsd relays to the web server
    app->sfd = sfd;
    // Setup buffers to some reasonable size
    vector_reserve (&app->rbuf, 4096);
    vector_reserve (&app->wbuf, 4096);
    // Send a standard GET request
    int bw = snprintf (app->wbuf.d, app->wbuf.allocated, "GET / HTTP/1.1\nHost: 192.168.1.1\n\n");
    if ((size_t) bw >= app->wbuf.allocated)
	return casycom_error ("snprintf: %s", strerror(errno));
    app->wbuf.size = bw;
    // Setup the asynchronous socket IO object, which will send us
    // IOR_Read when data is available, and IOR_Written when wbuf has
    // been written (IOR_Written is not used in this demo)
    PFdIO_attach (&app->sio, sfd);
    PIO_read (&app->sio, &app->rbuf);
    PIO_write (&app->sio, &app->wbuf);
}

static void App_IOR_read (App* app, CharVector* d)
{
    // d will be NULL when the server closes the connection
    if (!d)
	return casycom_quit (EXIT_SUCCESS);
    // Now print the web page received from the server
    fflush (stdout);
    while (d->size) {
	// remove some private information, so I could keep an
	// .std output template for automated checking.
	const char* pdate = strstr (d->d, "Date: "), *pnl;
	if (pdate && ((pnl = strchr (pdate, '\n'))))
	    vector_erase_n (d, pdate - d->d, pnl-pdate+1);
	pdate = strstr (d->d, "WWW-Authenticate: ");
	if (pdate && ((pnl = strchr (pdate, '\n'))))
	    vector_erase_n (d, pdate - d->d, pnl-pdate+1);

	// Then write to stdout
	ssize_t bw = write (STDOUT_FILENO, d->d, d->size);
	if (bw <= 0) {
	    if (errno == EINTR)
		continue;
	    return casycom_error ("write: %s", strerror(errno));
	}
	vector_erase_n (d, 0, bw);
    }
    // And keep reading while the server keeps sending
    PIO_read (&app->sio, d);
}

//----------------------------------------------------------------------

// These are object vtables. See casycom documentation for a tutorial.
static const DApp d_App_App = {
    .interface = &i_App,
    DMETHOD (App, App_init)
};
static const DExternR d_App_ExternR = {
    .interface = &i_ExternR,
    DMETHOD (App, ExternR_connected)
};
static const DTLSTunnelR d_App_TLSTunnelR = {
    .interface = &i_TLSTunnelR,
    DMETHOD (App, TLSTunnelR_connected)
};
static const DIOR d_App_IOR = {
    .interface = &i_IOR,
    DMETHOD (App, IOR_read)
};
static const Factory f_App = {
    .create     = App_create,
    .destroy    = App_destroy,
    .dtable     = { &d_App_App, &d_App_ExternR, &d_App_TLSTunnelR, &d_App_IOR, NULL }
};

CASYCOM_MAIN (f_App)
