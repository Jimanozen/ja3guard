# ja3guard

ja3guard is a HTTP reverse-proxy which calculates the client's ja3 fingerprint and sends it in an HTTP header to the endpoint

## Features
 - Multithread connection
 - TOML configuration
 - Facultative TLS connection to the endpoint
 - Facultative TLS client Certificate for authentiticated the proxy to the endpoint
 - Adding facultative customs HTTP headers to append into client HTTP orignal request.
 - Choose the TLS version to use for the proxy and its endpoint

## Dependencies 
- [libressl](http://libressl.org)
- [tomlc99](https://github.com/cktan/tomlc99)

