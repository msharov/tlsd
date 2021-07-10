// This file is part of the tlsd project
//
// Copyright (c) 2015 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#include "config.h"
#include "libtlsd.h"
#include <netdb.h>

enum EConnState {
    state_StartTLS,
    state_Handshake,
    state_Data
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
    Proxy		sio;
    unsigned short	sport;
    unsigned short	ststate;
} TLSTunnel;

//----------------------------------------------------------------------

static void TLSTunnel_ssl_error (const char* label);
static int TLSTunnel_verify_connection (int preverify, X509_STORE_CTX* x509_ctx);
static void TLSTunnel_do_io (TLSTunnel* o);

//----------------------------------------------------------------------

static void* TLSTunnel_create (const Msg* msg)
{
    TLSTunnel* po = xalloc (sizeof(TLSTunnel));
    po->sfd = -1;
    VECTOR_MEMBER_INIT (CharVector, po->obuf);
    VECTOR_MEMBER_INIT (CharVector, po->ibuf);
    po->reply = casycom_create_reply_proxy (&i_TLSTunnelR, msg);
    po->timer = casycom_create_proxy (&i_Timer, msg->h.dest);
    po->cio = casycom_create_proxy (&i_FdIO, msg->h.dest);
    po->sio = casycom_create_proxy (&i_FdIO, msg->h.dest);
    po->sslctx = SSL_CTX_new (SSLv23_method());
    if (!po->sslctx)
	TLSTunnel_ssl_error ("SSL_CTX_new");
    else {
	SSL_CTX_set_verify (po->sslctx, SSL_VERIFY_PEER, TLSTunnel_verify_connection);
	SSL_CTX_set_options (po->sslctx, SSL_OP_NO_SSLv2| SSL_OP_NO_SSLv3);
	if (1 != SSL_CTX_set_default_verify_paths (po->sslctx))
	    TLSTunnel_ssl_error ("SSL_CTX_set_default_verify_paths");
    }
    return po;
}

static void TLSTunnel_destroy (void* vo)
{
    TLSTunnel* o = vo;
    if (o) {
	if (o->ssl) {
	    if (o->cstate == state_Data)
		SSL_shutdown (o->ssl);
	    SSL_free (o->ssl);
	    o->ssl = NULL;
	}
	if (o->sslctx) {
	    SSL_CTX_free (o->sslctx);
	    o->sslctx = NULL;
	}
	if (o->sfd >= 0) {
	    close (o->sfd);
	    o->sfd = -1;
	}
	if (o->cfd >= 0) {
	    close (o->cfd);
	    o->cfd = -1;
	}
    }
    xfree (o);
}

static void TLSTunnel_TLSTunnel_open (TLSTunnel* o, const char* host, const char* port)
{
    // Lookup the host address
    struct addrinfo* ai = NULL;
    for (unsigned ntry = 0;;) {
	static const struct addrinfo hints = { .ai_family = PF_UNSPEC, .ai_socktype = SOCK_STREAM };
	int gar = getaddrinfo (host, port, &hints, &ai);
	if (gar == EAI_AGAIN && ntry++ <= 15) {
	    sleep (1);
	    continue;
	} else if (gar < 0 || !ai)
	    return casycom_error ("getaddrinfo: %s", strerror(errno));
	break;
    }

    // Create the socket
    o->sfd = socket (ai->ai_family, SOCK_STREAM| SOCK_NONBLOCK| SOCK_CLOEXEC, ai->ai_protocol);
    if (o->sfd < 0)
	return casycom_error ("socket: %s", strerror(errno));
    if (ai->ai_family == PF_INET)
	o->sport = ntohs (((const struct sockaddr_in*) ai->ai_addr)->sin_port);
    if (0 > connect (o->sfd, ai->ai_addr, ai->ai_addrlen) && errno != EINPROGRESS)
	return casycom_error ("connect: %s", strerror(errno));
    freeaddrinfo (ai);

    // Create new SSL state tracker
    o->ssl = SSL_new (o->sslctx);
    if (!o->ssl)
	return casycom_error ("SSL_new failed");
    SSL_set_fd (o->ssl, o->sfd);
    // Disable weak ciphers
    long r = SSL_set_cipher_list (o->ssl, "DEFAULT:!EXPORT:!LOW:!MEDIUM:!RC2:!3DES:!MD5:!DSS:!SEED:!RC4:!PSK:@STRENGTH");
    if (r != 1)
	return TLSTunnel_ssl_error ("SSL_set_cipher_list");

    vector_reserve (&o->ibuf, INT16_MAX);
    vector_reserve (&o->obuf, INT16_MAX);

    // Check if STARTTLS is needed
    if (o->sport == 587 || o->sport == 25) {
	o->cstate = state_StartTLS;
	PFdIO_attach (&o->sio, o->sfd);
	char hostname [HOST_NAME_MAX] = "localhost";
	gethostname (ARRAY_BLOCK (hostname));
	o->obuf.size = snprintf (o->obuf.d, o->obuf.allocated, "EHLO %s\r\n", hostname);
	PIO_write (&o->sio, &o->obuf);
	PIO_read (&o->sio, &o->ibuf);
    } else {
	o->cstate = state_Handshake;
	TLSTunnel_do_io (o);
    }
}

static void TLSTunnel_do_io (TLSTunnel* o)
{
    enum ETimerWatchCmd scmd = 0;
    if (o->cstate == state_Handshake) {
	// Do handshake
	int r;
	if (1 != (r = SSL_connect (o->ssl))) {
	    int sslerr = SSL_get_error (o->ssl, r);
	    if (!r || sslerr == SSL_ERROR_ZERO_RETURN)	// SSL server closed connection
		return casycom_error ("SSL_connect: handshake unsuccessful");
	    else if (sslerr == SSL_ERROR_WANT_READ)
		scmd |= WATCH_READ;
	    else if (sslerr == SSL_ERROR_WANT_WRITE)
		scmd |= WATCH_WRITE;
	    else if (sslerr == SSL_ERROR_SYSCALL)
		return casycom_error ("SSL_connect: %s", strerror(errno));
	    else
		return TLSTunnel_ssl_error ("SSL_connect");
	} else {	// handshake successful
	    // Verify a server certifcate was presented during negotiation
	    X509* cert = SSL_get_peer_certificate (o->ssl);
	    if (!cert)
		return TLSTunnel_ssl_error ("no peer certificate");
	    else
		X509_free (cert);
	    // create client data pipe
	    int cfdp[2];
	    if (0 > socketpair (PF_LOCAL, SOCK_STREAM| SOCK_NONBLOCK, IPPROTO_IP, cfdp))
		return casycom_error ("socketpair: %s", strerror(errno));
	    o->cfd = cfdp[0];
	    PTLSTunnelR_connected (&o->reply, cfdp[1]);
	    PFdIO_attach (&o->cio, o->cfd);
	    o->cstate = state_Data;
	}
    }
    if (o->cstate == state_Data) {
	while (o->obuf.size) {
	    ssize_t r;
	    if (0 >= (r = SSL_write (o->ssl, o->obuf.d, o->obuf.size))) {
		int sslerr = SSL_get_error (o->ssl, r);
		if (!r || sslerr == SSL_ERROR_ZERO_RETURN)	// SSL server closed connection
		    casycom_mark_unused (o);
		else if (sslerr == SSL_ERROR_WANT_READ)
		    scmd |= WATCH_READ;
		else if (sslerr == SSL_ERROR_WANT_WRITE)
		    scmd |= WATCH_WRITE;
		else if (sslerr == SSL_ERROR_SYSCALL)
		    return casycom_error ("SSL_write: %s", strerror(errno));
		else
		    return TLSTunnel_ssl_error ("SSL_write");
		break;
	    } else
		vector_erase_n (&o->obuf, 0, r);
	}
	for (size_t btr; (btr = o->ibuf.allocated - o->ibuf.size);) {
	    ssize_t r;
	    if (0 >= (r = SSL_read (o->ssl, &o->ibuf.d[o->ibuf.size], btr))) {
		int sslerr = SSL_get_error (o->ssl, r);
		if (!r || sslerr == SSL_ERROR_ZERO_RETURN)	// SSL server closed connection
		    casycom_mark_unused (o);
		else if (sslerr == SSL_ERROR_WANT_READ)
		    scmd |= WATCH_READ;
		else if (sslerr == SSL_ERROR_WANT_WRITE)
		    scmd |= WATCH_WRITE;
		else if (sslerr == SSL_ERROR_SYSCALL)
		    return casycom_error ("SSL_read: %s", strerror(errno));
		else
		    return TLSTunnel_ssl_error ("SSL_read");
		break;
	    } else
		o->ibuf.size += r;
	}
	if (!o->obuf.size)
	    PIO_read (&o->cio, &o->obuf);
	if (o->ibuf.size)
	    PIO_write (&o->cio, &o->ibuf);
    }
    if (scmd)
	PTimer_watch (&o->timer, scmd, o->sfd, TIMER_NONE);
}

static bool GetSMTPResponse (const char* response, CharVector* d)
{
    const char* r = strstr (d->d, response);
    if (!r)
	return false;
    // Look for terminating newline
    const char* rend = strchr (r, '\n');
    if (!rend)
	return false;
    // Erase all data in d before and including the matching response
    vector_erase_n (d, 0, (rend+1)-d->d);
    d->d[d->size] = 0;	// restore 0-termination for further searches
    return true;
}

static void TLSTunnel_TimerR_timer (TLSTunnel* o, int fd UNUSED, const Msg* msg UNUSED)
{
    TLSTunnel_do_io (o);
}

static void TLSTunnel_IOR_read (TLSTunnel* o, CharVector* d)
{
    if (o->cstate != state_StartTLS)
	return TLSTunnel_do_io (o);

    // Do SMTP STARTTLS
    assert (d == &o->ibuf && "Client data received in STARTTLS state");
    assert ((o->sport == 25 || o->sport == 587) && "Only SMTP STARTTLS is currently implemented");
    // GetSMTPResponse uses strstr and needs 0-termination
    d->d[d->size] = 0;
    // looking for greeting 220
    if (o->ststate == 0 && GetSMTPResponse ("220 ", d))
	++o->ststate;
    // Looking for STARTTLS capability
    if (o->ststate == 1 && GetSMTPResponse ("STARTTLS", d)) {
	++o->ststate;
	assert (!o->obuf.size && "Received a response to an unwritten request");
	o->obuf.size = snprintf (o->obuf.d, o->obuf.allocated, "STARTTLS\r\n");
	PIO_write (&o->sio, &o->obuf);
	return;
    }
    // Looking for the STARTTLS acknowledgement
    if (o->ststate == 2 && GetSMTPResponse ("220 ", d))
	++o->ststate;
    // "502 unimplemented" is the only possible error
    if (GetSMTPResponse ("502 ", d))
	return casycom_error ("server does not support STARTTLS");

    // Keep waiting for response until STARTTLS is acknowledged
    if (o->ststate < 3)
	return;

    // Done reading
    // Stop reading directly from the server socket. OpenSSL will do that now.
    assert (!o->obuf.size && "Received a response to an unwritten request");
    assert (!o->ibuf.size && "Server wrote non-SSL data after STARTTLS");
    vector_clear (&o->ibuf);
    o->obuf.size = snprintf (o->obuf.d, o->obuf.allocated, "NOOP\r\n");
    PIO_read (&o->sio, NULL);
    // Go to SSL negotiation
    o->cstate = state_Handshake;
    PTimer_watch (&o->timer, WATCH_READ| WATCH_WRITE, o->sfd, TIMER_NONE);
}

static void TLSTunnel_IOR_written (TLSTunnel* o, CharVector* v UNUSED)
{
    TLSTunnel_do_io (o);
}

static void TLSTunnel_ssl_error (const char* label)
{
    unsigned long err = ERR_get_error();
    const char* errstr = ERR_reason_error_string(err);
    if (errstr)
	casycom_error ("%s: %s", label, errstr);
    else
	casycom_error ("%s failed with code 0x%lx", label, err);
}

static int TLSTunnel_verify_connection (int preverify, X509_STORE_CTX* x509_ctx)
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
    DMETHOD (TLSTunnel, TLSTunnel_open)
};
static const DTimerR d_TLSTunnel_TimerR = {
    .interface = &i_TimerR,
    DMETHOD (TLSTunnel, TimerR_timer)
};
static const DIOR d_TLSTunnel_IOR = {
    .interface = &i_IOR,
    DMETHOD (TLSTunnel, IOR_read),
    DMETHOD (TLSTunnel, IOR_written)
};
const Factory f_TLSTunnel = {
    .create = TLSTunnel_create,
    .destroy = TLSTunnel_destroy,
    .dtable = { &d_TLSTunnel_TLSTunnel, &d_TLSTunnel_TimerR, &d_TLSTunnel_IOR, NULL }
};
