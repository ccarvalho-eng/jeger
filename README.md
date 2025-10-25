# Skjold

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

## Usage

```bash
# Scan network for Erlang nodes
./_build/default/bin/skjold -r 192.168.1.1-254

# Custom timeout and concurrency
./_build/default/bin/skjold -r 10.0.0.1-100 -t 2000 -c 100
```

## Programmatic API

```erlang
%% Discovery
{ok, Hosts} = skjold_discovery:discover({"192.168.1.", 1, 254}, #{}).

%% Enumeration
{ok, Info} = skjold_enum:enumerate_node("192.168.1.5", "myapp", secret).

%% Vulnerability Scan
{ok, Findings} = skjold_scan:scan_node("192.168.1.5", "myapp", secret).

%% Exploitation
{ok, Result} = skjold_exploit:execute_command("192.168.1.5", "myapp", secret, "os:cmd(\"whoami\")").
```

## Testing

```bash
rebar3 eunit
```

## Warning

**For authorized security assessments only.** Unauthorized access is illegal.

## License

Apache-2.0
