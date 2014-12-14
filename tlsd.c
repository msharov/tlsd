// This file is part of the tlsd project
//
// Copyright (c) 2014 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "config.h"
#if !HAVE_OPENSSL_BIO_H || !HAVE_OPENSSL_SSL_H || !HAVE_OPENSSL_ERR_H
    #error "tlsd requires the OpenSSL library"
#endif
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

int main (void)
{
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    puts ("Hello world!");
    return EXIT_SUCCESS;
}
