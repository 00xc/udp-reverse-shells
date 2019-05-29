# udp-reverse-shell
Dumb UDP reverse shell for *nix systems.\
\
I didn't find an example anywhere online for a UDP reverse shell in C so that's that.\
The only difference from a TCP reverse shell is that a UDP message needs to be sent first to the recipient because there is no such thing as a UDP connection.

Test IPv4:\
`nc -nlvup 9999`

Test IPv6:\
`ncat -nluvp 9999`
