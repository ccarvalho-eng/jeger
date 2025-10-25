-module(jeger_discovery_tests).

-include_lib("eunit/include/eunit.hrl").

discover_small_range_test() ->
    Result = jeger_discovery:discover({"192.168.255.", 1, 2}, #{timeout => 100, verbose => false}),
    ?assertMatch({ok, _}, Result),
    {ok, Hosts} = Result,
    ?assert(is_list(Hosts)).

format_results_empty_test() ->
    Output = jeger_discovery:format_results([]),
    ?assert(is_list(Output)),
    ?assert(length(Output) > 0).

format_results_with_nodes_test() ->
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
    Output = jeger_discovery:format_results(MockResults),
    ?assert(is_list(Output)),
    ?assert(length(Output) > 0),
    ?assert(string:str(Output, "192.168.1.1") > 0),
    ?assert(string:str(Output, "test@192.168.1.1") > 0).

format_results_no_nodes_test() ->
    MockResults = [
        #{
            host => "10.0.0.1",
            epmd => available,
            nodes => [],
            discovered_at => erlang:system_time(second)
        }
    ],
    Output = jeger_discovery:format_results(MockResults),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "10.0.0.1") > 0),
    ?assert(string:str(Output, "No nodes registered") > 0).

discover_with_verbose_option_test() ->
    Result = jeger_discovery:discover({"192.168.255.", 1, 2}, #{timeout => 100, verbose => true}),
    ?assertMatch({ok, _}, Result).
