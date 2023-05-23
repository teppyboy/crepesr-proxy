# CrepeSR-Proxy

This is a proxy server for CrepeSR. It is used to forward requests to the CrepeSR server.

## Why?

Fuck Fiddle Classic, we Linux gang.

## Features

+ Automatic mitmproxy configuration & certificate installation.
+ Automatic set/unset system proxy.
+ Connect to your own CrepeSR instance by setting `SERVER_ADDRESS` env
+ Works on Windows & Linux.

## Usage

### From source

Assuming you have `poetry` installed:

1. Clone the repository
2. Run `poetry install`
3. Run `poetry run python -m crepesr_proxy`

By default it'll start a HTTP proxy server in `127.0.0.1:13168`

## License

[MIT](./LICENSE)
