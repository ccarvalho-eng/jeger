%%%-------------------------------------------------------------------
%%% @doc
%%% Command-line interface for Jeger pentesting tool.
%%% @end
%%%-------------------------------------------------------------------
-module(jeger_cli).

-export([main/1]).

-define(DEFAULT_TIMEOUT, 1000).
-define(DEFAULT_CONCURRENCY, 50).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Main entry point for escript
-dialyzer({no_return, main/1}).
main(Args) ->
    case parse_args(Args) of
        {ok, #{help := true}} ->
            print_help(),
            halt(0);
        {ok, Opts} ->
            run_discovery(Opts);
        {error, Reason} ->
            io:format("Error: ~s~n~n", [Reason]),
            print_help(),
            halt(1)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
parse_args(Args) ->
    try
        parse_args(Args, #{verbose => true})
    catch
        throw:{error, Reason} ->
            {error, Reason}
    end.

parse_args([], Opts) ->
    case maps:is_key(range, Opts) of
        true -> {ok, Opts};
        false -> {error, "IP range is required (-r or --range)"}
    end;
parse_args(["-h" | _], _Opts) ->
    {ok, #{help => true}};
parse_args(["--help" | _], _Opts) ->
    {ok, #{help => true}};
parse_args(["-r", Range | Rest], Opts) ->
    case parse_range(Range) of
        {ok, ParsedRange} ->
            parse_args(Rest, Opts#{range => ParsedRange});
        {error, Reason} ->
            throw({error, Reason})
    end;
parse_args(["--range", Range | Rest], Opts) ->
    case parse_range(Range) of
        {ok, ParsedRange} ->
            parse_args(Rest, Opts#{range => ParsedRange});
        {error, Reason} ->
            throw({error, Reason})
    end;
parse_args(["-t", Timeout | Rest], Opts) ->
    case string:to_integer(Timeout) of
        {Int, ""} when Int > 0 ->
            parse_args(Rest, Opts#{timeout => Int});
        _ ->
            throw({error, "Invalid timeout value"})
    end;
parse_args(["--timeout", Timeout | Rest], Opts) ->
    case string:to_integer(Timeout) of
        {Int, ""} when Int > 0 ->
            parse_args(Rest, Opts#{timeout => Int});
        _ ->
            throw({error, "Invalid timeout value"})
    end;
parse_args(["-c", Concurrency | Rest], Opts) ->
    case string:to_integer(Concurrency) of
        {Int, ""} when Int > 0 ->
            parse_args(Rest, Opts#{concurrency => Int});
        _ ->
            throw({error, "Invalid concurrency value"})
    end;
parse_args(["--concurrency", Concurrency | Rest], Opts) ->
    case string:to_integer(Concurrency) of
        {Int, ""} when Int > 0 ->
            parse_args(Rest, Opts#{concurrency => Int});
        _ ->
            throw({error, "Invalid concurrency value"})
    end;
parse_args(["-q" | Rest], Opts) ->
    parse_args(Rest, Opts#{verbose => false});
parse_args(["--quiet" | Rest], Opts) ->
    parse_args(Rest, Opts#{verbose => false});
parse_args([Unknown | _], _Opts) ->
    throw({error, io_lib:format("Unknown option: ~s", [Unknown])}).

%% @private
parse_range(Range) ->
    case string:split(Range, "-") of
        [StartIP, EndStr] ->
            case parse_ip_and_octet(StartIP) of
                {ok, BaseIP, StartOctet} ->
                    case string:to_integer(EndStr) of
                        {EndOctet, ""} when EndOctet >= 1, EndOctet =< 254 ->
                            if
                                StartOctet =< EndOctet ->
                                    {ok, {BaseIP, StartOctet, EndOctet}};
                                true ->
                                    {error, "Start octet must be <= end octet"}
                            end;
                        _ ->
                            {error, "Invalid end octet (must be 1-254)"}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            {error, "Invalid range format. Expected: 192.168.1.1-254"}
    end.

%% @private
parse_ip_and_octet(IP) ->
    Parts = string:split(IP, ".", all),
    case length(Parts) of
        4 ->
            [Oct1, Oct2, Oct3, Oct4] = Parts,
            case string:to_integer(Oct4) of
                {LastOctet, ""} when LastOctet >= 1, LastOctet =< 254 ->
                    BaseIP = Oct1 ++ "." ++ Oct2 ++ "." ++ Oct3 ++ ".",
                    {ok, BaseIP, LastOctet};
                _ ->
                    {error, "Invalid start IP address"}
            end;
        _ ->
            {error, "Invalid IP address format"}
    end.

%% @private
run_discovery(Opts) ->
    Range = maps:get(range, Opts),
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    Concurrency = maps:get(concurrency, Opts, ?DEFAULT_CONCURRENCY),
    Verbose = maps:get(verbose, Opts, true),

    print_banner(),

    DiscoveryOpts = #{
        timeout => Timeout,
        concurrency => Concurrency,
        verbose => Verbose
    },

    {ok, Results} = jeger_discovery:discover(Range, DiscoveryOpts),
    Output = jeger_discovery:format_results(Results),
    io:put_chars(Output),
    case length(Results) of
        0 -> halt(1);
        _ -> halt(0)
    end.

%% @private
print_banner() ->
    io:format("~n"),
    io:format("     ██╗███████╗ ██████╗ ███████╗██████╗ ~n"),
    io:format("     ██║██╔════╝██╔════╝ ██╔════╝██╔══██╗~n"),
    io:format("     ██║█████╗  ██║  ███╗█████╗  ██████╔╝~n"),
    io:format("██   ██║██╔══╝  ██║   ██║██╔══╝  ██╔══██╗~n"),
    io:format("╚█████╔╝███████╗╚██████╔╝███████╗██║  ██║~n"),
    io:format(" ╚════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝~n"),
    io:format("~n"),
    io:format("  BEAM Node Discovery & Pentesting Tool~n"),
    io:format("~n").

%% @private
print_help() ->
    io:format("~n"),
    io:format("Jeger - BEAM Node Discovery & Pentesting Tool~n"),
    io:format("~n"),
    io:format("USAGE:~n"),
    io:format("    jeger [OPTIONS]~n"),
    io:format("~n"),
    io:format("OPTIONS:~n"),
    io:format("    -r, --range RANGE          IP range to scan (e.g., '192.168.1.1-254') [required]~n"),
    io:format("    -t, --timeout MS           Connection timeout in milliseconds (default: 1000)~n"),
    io:format("    -c, --concurrency N        Number of concurrent scanners (default: 50)~n"),
    io:format("    -q, --quiet                Suppress progress messages~n"),
    io:format("    -h, --help                 Show this help message~n"),
    io:format("~n"),
    io:format("EXAMPLES:~n"),
    io:format("    # Scan local network for Erlang nodes~n"),
    io:format("    jeger -r 192.168.1.1-254~n"),
    io:format("~n"),
    io:format("    # Scan with custom timeout and concurrency~n"),
    io:format("    jeger -r 10.0.0.1-100 -t 2000 -c 100~n"),
    io:format("~n"),
    io:format("    # Quiet mode (results only)~n"),
    io:format("    jeger -r 172.16.0.1-254 --quiet~n"),
    io:format("~n"),
    io:format("DESCRIPTION:~n"),
    io:format("    Jeger discovers Erlang/Elixir nodes by scanning for EPMD~n"),
    io:format("    (Erlang Port Mapper Daemon) services on the network. It queries~n"),
    io:format("    EPMD to enumerate registered node names and their distribution ports.~n"),
    io:format("~n"),
    io:format("    This tool is intended for authorized security assessments and~n"),
    io:format("    educational purposes only.~n"),
    io:format("~n").
