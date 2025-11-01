%%%-------------------------------------------------------------------
%%% @doc
%%% Vulnerability scanner for Erlang/BEAM nodes.
%%% Detects common misconfigurations and security issues.
%%% @end
%%%-------------------------------------------------------------------
-module(jeger_scan).

-export([
    scan_node/3,
    scan_vulnerabilities/1,
    format_findings/1
]).

-define(WEAK_COOKIES, [cookie, secret, test, admin, erlang, password]).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Scan a node for vulnerabilities
-spec scan_node(string(), string(), atom()) -> {ok, map()} | {error, term()}.
scan_node(Host, NodeName, Cookie) ->
    TargetNode = list_to_atom(NodeName ++ "@" ++ Host),
    NameType = detect_name_type(Host),
    ensure_distributed(Cookie, NameType),

    case net_adm:ping(TargetNode) of
        pong ->
            Findings = check_vulnerabilities(TargetNode, Cookie),
            {ok, #{node => TargetNode, findings => Findings}};
        pang ->
            {error, connection_failed}
    end.

%% @doc Scan for vulnerabilities from enumeration data
-spec scan_vulnerabilities(map()) -> [{node, term()} | {findings, [map()]}, ...].
scan_vulnerabilities(#{node := Node, security := Security} = _EnumData) ->
    Findings = [],
    Findings1 = check_cookie_security(Security, Findings),
    Findings2 = check_distribution_protocol(Security, Findings1),
    [{node, Node}, {findings, Findings2}].

%% @doc Format vulnerability findings
-spec format_findings(map()) -> string().
format_findings(#{node := Node, findings := Findings}) ->
    Severity = calculate_severity(Findings),
    lists:flatten([
        io_lib:format("~n[!] Vulnerability Scan: ~p~n", [Node]),
        io_lib:format("  Severity: ~s~n", [Severity]),
        io_lib:format("  Findings: ~p~n", [length(Findings)]),
        format_finding_list(Findings)
    ]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

detect_name_type(Host) ->
    case string:find(Host, ".") of
        nomatch ->
            case lists:member($., Host) of
                false -> shortnames;
                true -> longnames
            end;
        _ -> longnames
    end.

ensure_distributed(Cookie, NameType) ->
    case node() of
        nonode@nohost ->
            ScannerNode = generate_node_name(NameType),
            net_kernel:start([ScannerNode, NameType]),
            erlang:set_cookie(node(), Cookie);
        _ ->
            erlang:set_cookie(node(), Cookie)
    end.

generate_node_name(shortnames) ->
    Rand = rand:uniform(99999),
    list_to_atom("jeger_scan_" ++ integer_to_list(Rand));
generate_node_name(longnames) ->
    Rand = rand:uniform(99999),
    {ok, Hostname} = inet:gethostname(),
    list_to_atom("jeger_scan_" ++ integer_to_list(Rand) ++ "@" ++ Hostname).

check_vulnerabilities(TargetNode, Cookie) ->
    Checks = [
        fun() -> check_weak_cookie(Cookie) end,
        fun() -> check_code_loading(TargetNode) end,
        fun() -> check_shell_access(TargetNode) end
    ],
    lists:filtermap(fun(Check) ->
        case Check() of
            {vuln, Finding} -> {true, Finding};
            ok -> false
        end
    end, Checks).

check_weak_cookie(Cookie) ->
    case lists:member(Cookie, ?WEAK_COOKIES) of
        true ->
            {vuln, #{
                type => weak_cookie,
                severity => critical,
                description => "Node uses weak/default cookie",
                cookie => Cookie
            }};
        false ->
            ok
    end.

check_code_loading(TargetNode) ->
    case rpc:call(TargetNode, code, get_mode, [], 5000) of
        interactive ->
            {vuln, #{
                type => code_loading_enabled,
                severity => high,
                description => "Interactive code loading enabled"
            }};
        _ ->
            ok
    end.

check_shell_access(TargetNode) ->
    case rpc:call(TargetNode, init, get_argument, [remsh], 5000) of
        {ok, _} ->
            {vuln, #{
                type => remote_shell_enabled,
                severity => medium,
                description => "Remote shell access enabled"
            }};
        _ ->
            ok
    end.

check_cookie_security(#{cookie_visible := true}, Findings) ->
    [#{
        type => cookie_exposed,
        severity => high,
        description => "Cookie is readable via RPC"
    } | Findings];
check_cookie_security(_, Findings) ->
    Findings.

check_distribution_protocol(#{distribution_protocol := Proto}, Findings)
  when Proto =/= inet_tls ->
    [#{
        type => unencrypted_distribution,
        severity => medium,
        description => "Distribution protocol not using TLS"
    } | Findings];
check_distribution_protocol(_, Findings) ->
    Findings.

calculate_severity(Findings) ->
    case lists:any(fun(#{severity := S}) -> S =:= critical end, Findings) of
        true -> "CRITICAL";
        false ->
            case lists:any(fun(#{severity := S}) -> S =:= high end, Findings) of
                true -> "HIGH";
                false -> "MEDIUM"
            end
    end.

format_finding_list([]) ->
    "  No vulnerabilities found~n";
format_finding_list(Findings) ->
    [format_finding(F) || F <- Findings].

format_finding(#{type := Type, severity := Sev, description := Desc}) ->
    io_lib:format("  - [~s] ~s: ~s~n", [string:uppercase(atom_to_list(Sev)), Type, Desc]).
