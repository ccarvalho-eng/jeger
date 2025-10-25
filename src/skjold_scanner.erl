%%%-------------------------------------------------------------------
%%% @doc
%%% Network scanner for discovering EPMD services and Erlang nodes.
%%% Provides concurrent scanning of IP ranges.
%%% @end
%%%-------------------------------------------------------------------
-module(skjold_scanner).

-export([
    scan_range/1,
    scan_range/2,
    scan_hosts/1,
    scan_hosts/2,
    ping_node/2,
    ping_node/3
]).

-define(DEFAULT_TIMEOUT, 1000).
-define(DEFAULT_CONCURRENCY, 50).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Scan an IP range for EPMD services
%% Range format: {BaseIP, Start, End}
%% Example: {"192.168.1.", 1, 254}
-spec scan_range({string(), pos_integer(), pos_integer()}) ->
    {ok, [map()]}.
scan_range(Range) ->
    scan_range(Range, #{}).

-spec scan_range({string(), pos_integer(), pos_integer()}, map()) ->
    {ok, [map()]}.
scan_range({BaseIP, Start, End}, Opts) ->
    Hosts = generate_hosts(BaseIP, Start, End),
    scan_hosts(Hosts, Opts).

%% @doc Scan a list of hosts for EPMD services and registered nodes
-spec scan_hosts([string()]) -> {ok, [map()]}.
scan_hosts(Hosts) ->
    scan_hosts(Hosts, #{}).

-spec scan_hosts([string()], map()) -> {ok, [map()]}.
scan_hosts(Hosts, Opts) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    Concurrency = maps:get(concurrency, Opts, ?DEFAULT_CONCURRENCY),

    Parent = self(),
    Collector = spawn_link(fun() -> collector(Parent, length(Hosts), []) end),

    %% Spawn scanner processes with concurrency limit
    spawn_scanners(Hosts, Collector, Timeout, Concurrency),

    %% Wait for results
    receive
        {scan_complete, Results} -> {ok, Results}
    after
        (Timeout * 2) + 5000 ->
            {ok, []}
    end.

%% @doc Attempt to ping an Erlang node
-spec ping_node(string(), atom()) -> pong | pang.
ping_node(Host, Cookie) ->
    ping_node(Host, Cookie, ?DEFAULT_TIMEOUT).

-spec ping_node(string(), atom(), timeout()) -> pong | pang.
ping_node(Host, Cookie, _Timeout) ->
    %% Generate unique node name for this scan attempt
    ScannerNode = generate_scanner_node(),

    %% Start distributed if not already
    case net_kernel:start([ScannerNode, shortnames]) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok;
        _ -> ok
    end,

    %% Set cookie
    erlang:set_cookie(node(), Cookie),

    %% Attempt ping
    TargetNode = list_to_atom("target@" ++ Host),
    Result = net_adm:ping(TargetNode),

    Result.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
generate_hosts(BaseIP, Start, End) ->
    [BaseIP ++ integer_to_list(N) || N <- lists:seq(Start, End)].

%% @private
spawn_scanners(Hosts, Collector, Timeout, Concurrency) ->
    spawn_scanners(Hosts, Collector, Timeout, Concurrency, 0).

spawn_scanners([], _Collector, _Timeout, _Concurrency, _Active) ->
    ok;
spawn_scanners(Hosts, Collector, Timeout, Concurrency, Active) when Active >= Concurrency ->
    %% Wait for a slot to open
    receive
        {scanner_done} ->
            spawn_scanners(Hosts, Collector, Timeout, Concurrency, Active - 1)
    after
        Timeout * 2 ->
            spawn_scanners(Hosts, Collector, Timeout, Concurrency, Active)
    end;
spawn_scanners([Host | Rest], Collector, Timeout, Concurrency, Active) ->
    Parent = self(),
    spawn_link(fun() ->
        Result = scan_host(Host, Timeout),
        Collector ! {scan_result, Result},
        Parent ! {scanner_done}
    end),
    spawn_scanners(Rest, Collector, Timeout, Concurrency, Active + 1).

%% @private
scan_host(Host, Timeout) ->
    case skjold_epmd:check_epmd(Host, Timeout) of
        {ok, available} ->
            case skjold_epmd:query_names(Host, Timeout) of
                {ok, Nodes} ->
                    #{
                        host => Host,
                        epmd => available,
                        nodes => Nodes,
                        discovered_at => erlang:system_time(second)
                    };
                {error, _Reason} ->
                    #{
                        host => Host,
                        epmd => available,
                        nodes => [],
                        discovered_at => erlang:system_time(second)
                    }
            end;
        {error, _Reason} ->
            #{
                host => Host,
                epmd => unavailable
            }
    end.

%% @private
collector(Parent, Total, Acc) when length(Acc) >= Total ->
    %% Filter out hosts without EPMD
    Results = lists:filter(
        fun(#{epmd := Status}) -> Status =:= available end,
        Acc
    ),
    Parent ! {scan_complete, Results};
collector(Parent, Total, Acc) ->
    receive
        {scan_result, Result} ->
            collector(Parent, Total, [Result | Acc])
    after
        10000 ->
            %% Timeout - return what we have
            Results = lists:filter(
                fun(#{epmd := Status}) -> Status =:= available end,
                Acc
            ),
            Parent ! {scan_complete, Results}
    end.

%% @private
generate_scanner_node() ->
    Timestamp = erlang:system_time(millisecond),
    Rand = rand:uniform(9999),
    list_to_atom(lists:flatten(
        io_lib:format("skjold_scanner_~p_~p", [Timestamp, Rand])
    )).
