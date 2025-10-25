-module(skjold_discovery_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Tests
%%%===================================================================

discover_small_range_test() ->
    %% Test discovery on a small range
    Result = skjold_discovery:discover({"192.168.255.", 1, 2}, #{timeout => 100, verbose => false}),
    ?assertMatch({ok, _}, Result),
    {ok, Hosts} = Result,
    ?assert(is_list(Hosts)).

format_results_empty_test() ->
    %% Test formatting empty results
    Output = skjold_discovery:format_results([]),
    ?assert(is_list(Output)),
    ?assert(length(Output) > 0).

format_results_with_nodes_test() ->
    %% Test formatting results with mock data
    MockResults = [
        #{
            host => "192.168.1.1",
            epmd => available,
            nodes => [
                #{name => "test@192.168.1.1", port => 54321}
            ],
            discovered_at => erlang:system_time(second)
        }
    ],
    Output = skjold_discovery:format_results(MockResults),
    ?assert(is_list(Output)),
    ?assert(length(Output) > 0),
    %% Check that output contains key information
    ?assert(string:str(Output, "192.168.1.1") > 0),
    ?assert(string:str(Output, "test@192.168.1.1") > 0).
