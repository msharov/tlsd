// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "config.h"
#include "libtlsd.h"
#include <openssl/conf.h>

//----------------------------------------------------------------------

extern const Factory f_TLSTunnel;

//----------------------------------------------------------------------

typedef struct {
    Proxy	connp;
    int		sfd;
    Proxy	sio;
    CharVector	rbuf;
    CharVector	wbuf;
} App;

//----------------------------------------------------------------------

static void* App_Create (const Msg* msg UNUSED)
{
    static App app = { PROXY_INIT, -1, PROXY_INIT, VECTOR_INIT(CharVector), VECTOR_INIT(CharVector) };
    if (!app.connp.interface) {
	casycom_register (&f_Timer);
	casycom_register (&f_TLSTunnel);
	casycom_register (&f_FdIO);
	app.connp = casycom_create_proxy (&i_TLSTunnel, oid_App);
	app.sio = casycom_create_proxy (&i_FdIO, oid_App);
    }
    return &app;
}
static void App_Destroy (void* o UNUSED) {}

static void App_App_Init (App* app, unsigned argc UNUSED, const char* const* argv UNUSED)
{
    SSL_load_error_strings();
    SSL_library_init();
    OPENSSL_config (NULL);
    PTLSTunnel_Open (&app->connp, "192.168.1.1", "https");
}

static void App_IOR_Read (App* app, CharVector* d)
{
    if (!d)
	return casycom_quit (EXIT_SUCCESS);
    while (d->size) {
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
    .dtable     = { &d_App_App, &d_App_TLSTunnelR, &d_App_IOR, NULL }
};

CASYCOM_MAIN (f_App)
