%%%-------------------------------------------------------------------
%%% @doc
%%% Cluster-wide scanning for Jeger.
%%% Scans multiple nodes in a cluster and aggregates results.
%%% @end
%%%-------------------------------------------------------------------
-module(jeger_cluster).

-export([
    scan_cluster/3,
    scan_cluster/4,
    format_cluster_scan/1
]).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Scan multiple nodes in a cluster
-spec scan_cluster(string(), [string()], atom()) -> {ok, map()}.
scan_cluster(Host, NodeNames, Cookie) ->
    scan_cluster(Host, NodeNames, Cookie, #{verbose => true}).

%% @doc Scan cluster with options
-spec scan_cluster(string(), [string()], atom(), map()) -> {ok, map()}.
scan_cluster(Host, NodeNames, Cookie, Opts) ->
    Verbose = maps:get(verbose, Opts, true),

    case Verbose of
        true -> io:format("~n=== Scanning Cluster ===~n~n");
        false -> ok
    end,

    Results = lists:map(fun(NodeName) ->
        scan_single_node(Host, NodeName, Cookie, Verbose)
    end, NodeNames),

    Summary = calculate_summary(Results),

    case Verbose of
        true -> io:format("~n=== Scan Complete ===~n");
        false -> ok
    end,

    {ok, #{
        scanned => length(NodeNames),
        successful => length([R || #{status := ok} <- Results, R <- [ok]]),
        results => Results,
        summary => Summary
    }}.

%% @doc Format cluster scan results
-spec format_cluster_scan(map()) -> string().
format_cluster_scan(#{scanned := Total, successful := Success, summary := Summary}) ->
    lists:flatten([
        io_lib:format("~nCluster Scan Results:~n", []),
        io_lib:format("  Nodes Scanned: ~p~n", [Total]),
        io_lib:format("  Successful: ~p~n", [Success]),
        io_lib:format("  Total Vulnerabilities: ~p~n", [maps:get(total_findings, Summary, 0)]),
        io_lib:format("  Critical: ~p~n", [maps:get(critical, Summary, 0)]),
        io_lib:format("  High: ~p~n", [maps:get(high, Summary, 0)]),
        io_lib:format("  Medium: ~p~n", [maps:get(medium, Summary, 0)])
    ]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

scan_single_node(Host, NodeName, Cookie, Verbose) ->
    case Verbose of
        true -> io:format("[*] Scanning ~s@~s...~n", [NodeName, Host]);
        false -> ok
    end,

    EnumResult = jeger_enum:enumerate_node(Host, NodeName, Cookie),
    ScanResult = jeger_scan:scan_node(Host, NodeName, Cookie),

    Result = case {EnumResult, ScanResult} of
        {{ok, EnumData}, {ok, ScanData}} ->
            #{
                status => ok,
                node => list_to_atom(NodeName ++ "@" ++ Host),
                enumeration => EnumData,
                vulnerabilities => ScanData
            };
        {{error, EnumReason}, _} ->
            #{status => error, node => list_to_atom(NodeName ++ "@" ++ Host),
              reason => {enum_failed, EnumReason}};
        {_, {error, ScanReason}} ->
            #{status => error, node => list_to_atom(NodeName ++ "@" ++ Host),
              reason => {scan_failed, ScanReason}}
    end,

    case Verbose of
        true ->
            case Result of
                #{status := ok, enumeration := Enum, vulnerabilities := Vuln} ->
                    ProcessCount = maps:get(process_count, Enum, 0),
                    OTP = maps:get(otp_version, Enum, "unknown"),
                    Findings = maps:get(findings, Vuln, []),

                    io:format("  Process Count: ~p~n", [ProcessCount]),
                    io:format("  OTP: ~p~n", [OTP]),
                    io:format("  Vulnerabilities: ~p~n", [length(Findings)]),

                    lists:foreach(fun(Finding) ->
                        Type = maps:get(type, Finding, unknown),
                        Severity = maps:get(severity, Finding, unknown),
                        Desc = maps:get(description, Finding, ""),
                        io:format("    [~p] ~p: ~s~n", [Severity, Type, Desc])
                    end, Findings),
                    io:format("~n");
                #{status := error, reason := Reason} ->
                    io:format("  Error: ~p~n~n", [Reason]);
                _ ->
                    ok
            end;
        false ->
            ok
    end,

    Result.

calculate_summary(Results) ->
    SuccessfulResults = [R || #{status := ok} = R <- Results],

    AllFindings = lists:flatten([
        maps:get(findings, maps:get(vulnerabilities, R, #{}), [])
        || R <- SuccessfulResults
    ]),

    #{
        total_findings => length(AllFindings),
        critical => count_severity(AllFindings, critical),
        high => count_severity(AllFindings, high),
        medium => count_severity(AllFindings, medium),
        low => count_severity(AllFindings, low)
    }.

count_severity(Findings, Severity) ->
    length([F || #{severity := S} = F <- Findings, S =:= Severity]).