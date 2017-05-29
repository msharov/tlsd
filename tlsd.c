// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "config.h"
#include "libtlsd.h"
#include <openssl/conf.h>

typedef struct { Proxy esrvp; } App;

static void* App_Create (const Msg* msg UNUSED)
    { static App app = { PROXY_INIT }; return &app; }
static void App_Destroy (void* o UNUSED) {}

static void App_App_Init (App* app, unsigned argc, char* const* argv)
{
    bool bPipeMode = false;
    for (int opt; 0 < (opt = getopt (argc, argv, "pd"));) {
	if (opt == 'p')
	    bPipeMode = true;
	else if (opt == 'd')
	    casycom_enable_debug_output();
	else {
	    printf (TLSD_NAME " " TLSD_VERSTRING "\n" TLSD_BUGREPORT
		    "\n\nUsage: " TLSD_NAME " [-pd]\n"
		    "  -p\tattach to socket pipe on stdin\n"
		    "  -d\tenable debug tracing\n");
	    exit (EXIT_SUCCESS);
	}
    }

    SSL_load_error_strings();
    SSL_library_init();
    if (CONF_modules_load_file (NULL, NULL, 0) <= 0) {
	printf ("Error: failed to load OpenSSL configuration\n");
	ERR_print_errors_fp (stdout);
	exit (EXIT_FAILURE);
    }

    casycom_enable_externs();
    extern const Factory f_TLSTunnel;
    casycom_register (&f_TLSTunnel);
    casycom_register (&f_FdIO);
    static const iid_t eil[] = { &i_TLSTunnel, NULL };
    if (bPipeMode) {
	app->esrvp = casycom_create_proxy (&i_Extern, oid_App);
        PExtern_Open (&app->esrvp, STDIN_FILENO, EXTERN_SERVER, NULL, eil);
    } else {
	casycom_register (&f_ExternServer);
	app->esrvp = casycom_create_proxy (&i_ExternServer, oid_App);
	if (sd_listen_fds())
	    PExternServer_Open (&app->esrvp, SD_LISTEN_FDS_START+0, eil, true);
	else if (0 > PExternServer_BindSystemLocal (&app->esrvp, TLSD_SOCKET, eil))
	    casycom_error ("ExternServer_BindSystemLocal: %s", strerror(errno));
    }
}

static void App_ObjectDestroyed (void* vo, oid_t oid)
{
    App* app = (App*) vo;
    if (oid == app->esrvp.dest && !casycom_is_quitting())
	casycom_quit (EXIT_SUCCESS);
}

//----------------------------------------------------------------------

static const DApp d_App_App = {
    .interface = &i_App,
    DMETHOD (App, App_Init)
};
static const DExternR d_App_ExternR = {
    .interface = &i_ExternR
};
static const Factory f_App = {
    .Create     = App_Create,
    .Destroy    = App_Destroy,
    .ObjectDestroyed = App_ObjectDestroyed,
    .dtable     = { &d_App_App, &d_App_ExternR, NULL }
};

CASYCOM_MAIN (f_App)
