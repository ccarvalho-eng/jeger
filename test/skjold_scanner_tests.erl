-module(skjold_scanner_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Tests
%%%===================================================================

scan_range_small_test() ->
    %% Test scanning a small range (should complete quickly even if no hosts found)
    Result = skjold_scanner:scan_range({"192.168.255.", 1, 3}, #{timeout => 100, concurrency => 10}),
    ?assertMatch({ok, _}, Result),
    {ok, Hosts} = Result,
    ?assert(is_list(Hosts)).

scan_hosts_empty_test() ->
    %% Test scanning empty list
    Result = skjold_scanner:scan_hosts([], #{timeout => 100}),
    ?assertEqual({ok, []}, Result).

scan_hosts_invalid_test() ->
    %% Test scanning invalid hosts
    Result = skjold_scanner:scan_hosts(["192.168.255.255"], #{timeout => 100, concurrency => 1}),
    ?assertMatch({ok, _}, Result).
