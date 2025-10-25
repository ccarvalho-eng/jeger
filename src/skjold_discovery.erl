%%%-------------------------------------------------------------------
%%% @doc
%%% Main discovery module for Skjold pentesting tool.
%%% Orchestrates EPMD scanning and node discovery operations.
%%% @end
%%%-------------------------------------------------------------------
-module(skjold_discovery).

-export([
    discover/1,
    discover/2,
    format_results/1
]).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Discover Erlang nodes in the given IP range
%% Options:
%%   - timeout: Connection timeout in milliseconds (default: 1000)
%%   - concurrency: Number of concurrent scanners (default: 50)
%%   - verbose: Print progress information (default: false)
-spec discover({string(), pos_integer(), pos_integer()}) ->
    {ok, [map()]}.
discover(Range) ->
    discover(Range, #{}).

-spec discover({string(), pos_integer(), pos_integer()}, map()) ->
    {ok, [map()]}.
discover({BaseIP, Start, End} = Range, Opts) ->
    Verbose = maps:get(verbose, Opts, false),

    case Verbose of
        true ->
            io:format("~n[*] Skjold Discovery Starting...~n"),
            io:format("[*] Target Range: ~s~p-~p~n", [BaseIP, Start, End]),
            io:format("[*] Scanning for EPMD services...~n~n");
        false ->
            ok
    end,

    %% Scan for EPMD services
    {ok, Results} = skjold_scanner:scan_range(Range, Opts),

    case Verbose of
        true ->
            io:format("[+] Scan Complete~n"),
            io:format("[+] Found ~p host(s) with EPMD running~n~n", [length(Results)]);
        false ->
            ok
    end,

    {ok, Results}.

%% @doc Format discovery results for display
-spec format_results([map()]) -> string().
format_results(Results) ->
    Header = io_lib:format(
        "~n~s~n~s~n~s~n",
        [
            "=" ++ lists:duplicate(70, $=),
            "  SKJOLD DISCOVERY RESULTS",
            "=" ++ lists:duplicate(70, $=)
        ]
    ),

    Summary = io_lib:format(
        "~nDiscovered: ~p host(s) with EPMD~n~n",
        [length(Results)]
    ),

    Details = lists:map(fun format_host/1, Results),

    Footer = io_lib:format(
        "~n~s~n",
        ["=" ++ lists:duplicate(70, $=)]
    ),

    lists:flatten([Header, Summary, Details, Footer]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
format_host(#{host := Host, nodes := Nodes, discovered_at := Timestamp}) ->
    Time = format_timestamp(Timestamp),
    NodeCount = length(Nodes),

    HostHeader = io_lib:format(
        "~n[~s] Host: ~s~n",
        [Time, Host]
    ),

    NodesInfo = case NodeCount of
        0 ->
            "  └─ No nodes registered~n";
        _ ->
            NodeLines = [format_node(N) || N <- Nodes],
            [
                io_lib:format("  └─ Registered Nodes (~p):~n", [NodeCount]),
                NodeLines
            ]
    end,

    lists:flatten([HostHeader, NodesInfo]).

%% @private
format_node(#{name := Name, port := Port}) ->
    io_lib:format("     • ~s (port: ~p)~n", [Name, Port]);
format_node(#{name := Name}) ->
    io_lib:format("     • ~s~n", [Name]).

%% @private
format_timestamp(Timestamp) ->
    {{Year, Month, Day}, {Hour, Minute, Second}} =
        calendar:system_time_to_universal_time(Timestamp, second),
    io_lib:format(
        "~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w UTC",
        [Year, Month, Day, Hour, Minute, Second]
    ).
