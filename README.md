# udp-reverse-shell
UDP reverse shells for *nix systems.\
\
I could not find an example anywhere online for a UDP reverse shell in C so I wrote several of them.

## Shells included ##
* Shell over UDP, IPv4 (udp_shell.c).
  - To test it, run first: `nc -nlvup 9999`
* Shell over UDP, IPv6: (udp_shell6.c).
   - To test it, run first: `ncat -nluvp 9999`
* Shell and listener over DLTS, UDP, IPv4:
  - Shell: dtls_shell.c
  - Listener: dtls_server.c
  - To test them, run the listener first and then the reverse shell.

## Compiling ##
Compiled with OpenSSL 1.0.2r (`sudo apt install libssl1.0-dev`)

`gcc <file.c> -o <binary> -lcrypto -lssl`
