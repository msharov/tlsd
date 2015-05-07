// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "config.h"
#include "libtlsd.h"
#include <netdb.h>

//{{{ TLSTunnel object

enum EConnState {
    state_Prewrite,
    state_Handshake,
    state_Data,
    state_Shutdown
};

typedef struct _TLSTunnel {
    Proxy		reply;
    int			sfd;
    Proxy		timer;
    enum EConnState	cstate;
    Proxy		cio;
    int			cfd;
    SSL_CTX*		sslctx;
    SSL*		ssl;
    CharVector		obuf;
    CharVector		ibuf;
} TLSTunnel;

//----------------------------------------------------------------------

static void TLSTunnel_SSLError (const char* label);
static int TLSTunnel_VerifyConnection (int preverify, X509_STORE_CTX* x509_ctx);
static void TLSTunnel_TimerR_Timer (TLSTunnel* o);

//----------------------------------------------------------------------

static void* TLSTunnel_Create (const Msg* msg)
{
    TLSTunnel* po = (TLSTunnel*) xalloc (sizeof(TLSTunnel));
    po->sfd = -1;
    VECTOR_MEMBER_INIT (CharVector, po->obuf);
    VECTOR_MEMBER_INIT (CharVector, po->ibuf);
    po->reply = casycom_create_reply_proxy (&i_TLSTunnelR, msg);
    po->timer = casycom_create_proxy (&i_Timer, msg->h.dest);
    po->cio = casycom_create_proxy (&i_FdIO, msg->h.dest);
    po->sslctx = SSL_CTX_new (SSLv23_method());
    if (!po->sslctx)
	TLSTunnel_SSLError ("SSL_CTX_new");
    else {
	SSL_CTX_set_verify (po->sslctx, SSL_VERIFY_PEER, TLSTunnel_VerifyConnection);
	SSL_CTX_set_options (po->sslctx, SSL_OP_NO_SSLv2| SSL_OP_NO_SSLv3);
	if (1 != SSL_CTX_set_default_verify_paths (po->sslctx))
	    TLSTunnel_SSLError ("SSL_CTX_set_default_verify_paths");
    }
    return po;
}

static void TLSTunnel_Destroy (void* vo)
{
    TLSTunnel* o = (TLSTunnel*) vo;
    if (o) {
	if (o->ssl) {
	    SSL_shutdown (o->ssl);
	    SSL_free (o->ssl);
	    o->ssl = NULL;
	}
	if (o->cfd >= 0) {
	    close (o->cfd);
	    o->cfd = -1;
	}
	if (o->sfd >= 0) {
	    close (o->sfd);
	    o->sfd = -1;
	}
	if (o->sslctx) {
	    SSL_CTX_free (o->sslctx);
	    o->sslctx = NULL;
	}
    }
    xfree (o);
}

static void TLSTunnel_TLSTunnel_Open (TLSTunnel* o, const char* host, const char* port)
{
    // Lookup the host address
    struct addrinfo* ai = NULL;
    static const struct addrinfo hints = { .ai_family = PF_UNSPEC, .ai_socktype = SOCK_STREAM };
    if (0 > getaddrinfo (host, port, &hints, &ai) || !ai)
	return casycom_error ("getaddrinfo: %s", strerror(errno));

    // Create the socket
    o->sfd = socket (ai->ai_family, SOCK_STREAM| SOCK_NONBLOCK| SOCK_CLOEXEC, ai->ai_protocol);
    if (o->sfd < 0)
	return casycom_error ("socket: %s", strerror(errno));
    if (0 > connect (o->sfd, ai->ai_addr, ai->ai_addrlen) && errno != EINPROGRESS)
	return casycom_error ("connect: %s", strerror(errno));
    freeaddrinfo (ai);

    // Create new SSL state tracker
    o->ssl = SSL_new (o->sslctx);
    if (!o->ssl)
	return casycom_error ("SSL_new failed");
    SSL_set_fd (o->ssl, o->sfd); long r;
    // Disable weak ciphers
    if (1 != (r = SSL_set_cipher_list (o->ssl, "aNULL:-aNULL:ALL:!EXPORT:!LOW:!MEDIUM:!RC2:!3DES:!MD5:!DSS:!SEED:!RC4:!PSK:@STRENGTH")))
	return TLSTunnel_SSLError ("SSL_set_cipher_list");

    vector_reserve (&o->ibuf, 4096);
    vector_reserve (&o->obuf, 4096);

    o->cstate = state_Handshake;
    TLSTunnel_TimerR_Timer (o);
}

static void TLSTunnel_TimerR_Timer (TLSTunnel* o)
{
    enum ETimerWatchCmd scmd = 0;
    if (o->cstate == state_Handshake) {
	// Do handshake
	int r;
	if (1 != (r = SSL_connect (o->ssl))) {
	    int sslerr = SSL_get_error (o->ssl, r);
	    if (sslerr == SSL_ERROR_ZERO_RETURN)	// SSL server closed connection
		casycom_mark_unused (o);
	    else if (sslerr == SSL_ERROR_WANT_READ)
		scmd |= WATCH_READ;
	    else if (sslerr == SSL_ERROR_WANT_WRITE)
		scmd |= WATCH_WRITE;
	    else
		return TLSTunnel_SSLError ("SSL_connect");
	} else {	// handshake successful
	    // Verify a server certifcate was presented during negotiation
	    X509* cert = SSL_get_peer_certificate (o->ssl);
	    if (!cert)
		return TLSTunnel_SSLError ("no peer certificate");
	    else
		X509_free (cert);
	    // Create client data pipe
	    int cfdp[2];
	    if (0 > socketpair (PF_LOCAL, SOCK_STREAM| SOCK_NONBLOCK| SOCK_CLOEXEC, IPPROTO_IP, cfdp))
		return casycom_error ("socketpair: %s", strerror(errno));
	    o->cfd = cfdp[0];
	    PTLSTunnelR_Connected (&o->reply, cfdp[1]);
	    PFdIO_Attach (&o->cio, o->cfd);
	    o->cstate = state_Data;
	}
    }
    if (o->cstate == state_Data) {
	while (o->obuf.size) {
	    ssize_t r;
	    if (0 >= (r = SSL_write (o->ssl, o->obuf.d, o->obuf.size))) {
		int sslerr = SSL_get_error (o->ssl, r);
		if (sslerr == SSL_ERROR_WANT_READ)
		    scmd |= WATCH_READ;
		else if (sslerr == SSL_ERROR_WANT_WRITE)
		    scmd |= WATCH_WRITE;
		else if (sslerr == SSL_ERROR_ZERO_RETURN)	// SSL server closed connection
		    casycom_mark_unused (o);
		else
		    return TLSTunnel_SSLError ("SSL_write");
		break;
	    } else
		vector_erase_n (&o->obuf, 0, r);
	}
	for (size_t btr; (btr = o->ibuf.allocated - o->ibuf.size);) {
	    ssize_t r;
	    if (0 >= (r = SSL_read (o->ssl, &o->ibuf.d[o->ibuf.size], btr))) {
		int sslerr = SSL_get_error (o->ssl, r);
		if (sslerr == SSL_ERROR_WANT_READ)
		    scmd |= WATCH_READ;
		else if (sslerr == SSL_ERROR_WANT_WRITE)
		    scmd |= WATCH_WRITE;
		else if (sslerr == SSL_ERROR_ZERO_RETURN)	// SSL server closed connection
		    casycom_mark_unused (o);
		else
		    return TLSTunnel_SSLError ("SSL_read");
		break;
	    } else
		o->ibuf.size += r;
	}
	if (!o->obuf.size)
	    PIO_Read (&o->cio, &o->obuf);
	if (o->ibuf.size)
	    PIO_Write (&o->cio, &o->ibuf);
    }
    if (scmd)
	PTimer_Watch (&o->timer, scmd, o->sfd, TIMER_NONE);
}

static void TLSTunnel_IOR_Read (TLSTunnel* o)
{
    TLSTunnel_TimerR_Timer (o);
}

static void TLSTunnel_IOR_Written (TLSTunnel* o)
{
    TLSTunnel_TimerR_Timer (o);
}

static void TLSTunnel_SSLError (const char* label)
{
    unsigned long err = ERR_get_error();
    const char* errstr = ERR_reason_error_string(err);
    if (errstr)
	casycom_error ("%s: %s\n", label, errstr);
    else
	casycom_error ("%s failed with code 0x%lx\n", label, err);
}

static int TLSTunnel_VerifyConnection (int preverify, X509_STORE_CTX* x509_ctx)
{
    if (!preverify) {
	int e = X509_STORE_CTX_get_error (x509_ctx);
	if (e != X509_V_OK && e != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN && e != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	    return false;
    }
    return true;
}

static const DTLSTunnel d_TLSTunnel_TLSTunnel = {
    .interface = &i_TLSTunnel,
    DMETHOD (TLSTunnel, TLSTunnel_Open)
};
static const DTimerR d_TLSTunnel_TimerR = {
    .interface = &i_TimerR,
    DMETHOD (TLSTunnel, TimerR_Timer)
};
static const DIOR d_TLSTunnel_IOR = {
    .interface = &i_IOR,
    DMETHOD (TLSTunnel, IOR_Read),
    DMETHOD (TLSTunnel, IOR_Written)
};
const Factory f_TLSTunnel = {
    .Create = TLSTunnel_Create,
    .Destroy = TLSTunnel_Destroy,
    .dtable = { &d_TLSTunnel_TLSTunnel, &d_TLSTunnel_TimerR, &d_TLSTunnel_IOR, NULL }
};

//}}}-------------------------------------------------------------------
