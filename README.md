# CrepeSR-Proxy

This is a proxy server for SR/YS private servers.

## Why?

Fuck Fiddle Classic, we Linux gang.

## Features

+ Automatic mitmproxy configuration & certificate installation.
+ Automatic set/unset system proxy.
+ Support YS proxy mode by starting with `--ys`
+ Connect to your own private server by setting `SERVER_ADDRESS` env/`--server-address` arg
+ Works on Windows & Linux.

## Usage

See `--help`

## Installation

### Binaries

soon:tm:

### From source

#### Install from source

You must have Python 3.11+ and git installed on your machine.

```bash
pip install -U git+https://github.com/teppyboy/crepesr_proxy
# Run the proxy
python -m crepesr_proxy
```

#### Running directly

Assuming you have `poetry` installed:

1. Clone the repository
2. Run `poetry install`
3. Run `poetry run python -m crepesr_proxy`

By default it'll start a HTTP proxy server in `127.0.0.1:13168` and set your system proxy.

## License

[MIT](./LICENSE)
