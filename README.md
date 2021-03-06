# TLSD

Many useful resources on the net these days require encrypted connections.
tlsd is an encrypting connection proxy, allowing you to talk to servers
over an encrypted connection without having to deal with OpenSSL directly.
Your program would connect to tlsd using the casycom API and get back
an open file descriptor that can be used as if it were an unencrypted
connection. Typical uses include fetching web pages, checking mail,
and sending mail (tlsd seamlessly supports SMTP STARTTLS).

Compiling tlsd requires a c11 compiler, like gcc 4.6+ or clang 3.2+, and
[casycom](https://github.com/msharov/casycom).
```sh
configure --prefix /usr && make install.
```

The test/tunnl.c program gives an example of how to download a web page
over https. It will try to get the login page of your router, if it
supports such a feature.

Report bugs using the github [bugtracker](https://github.com/msharov/tlsd/issues).
