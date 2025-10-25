-module(jeger_scanner_tests).

-include_lib("eunit/include/eunit.hrl").

scan_range_small_test() ->
    Result = jeger_scanner:scan_range({"192.168.255.", 1, 3}, #{timeout => 100, concurrency => 10}),
    ?assertMatch({ok, _}, Result),
    {ok, Hosts} = Result,
    ?assert(is_list(Hosts)).

scan_hosts_empty_test() ->
    Result = jeger_scanner:scan_hosts([], #{timeout => 100}),
    ?assertEqual({ok, []}, Result).

scan_hosts_invalid_test() ->
    Result = jeger_scanner:scan_hosts(["192.168.255.255"], #{timeout => 100, concurrency => 1}),
    ?assertMatch({ok, _}, Result).
