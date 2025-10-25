-module(jeger_epmd_tests).

-include_lib("eunit/include/eunit.hrl").

check_epmd_localhost_test() ->
    Result = jeger_epmd:check_epmd("localhost", 1000),
    ?assert(Result =:= {ok, available} orelse
            element(1, Result) =:= error).

check_epmd_invalid_host_test() ->
    Result = jeger_epmd:check_epmd("192.168.255.255", 100),
    ?assertMatch({error, _}, Result).

query_names_invalid_host_test() ->
    Result = jeger_epmd:query_names("192.168.255.255", 100),
    ?assertMatch({error, _}, Result).

query_port_invalid_host_test() ->
    Result = jeger_epmd:query_port("192.168.255.255", "testnode", 100),
    ?assertMatch({error, _}, Result).

query_port_with_atom_name_test() ->
    Result = jeger_epmd:query_port("192.168.255.255", testnode, 100),
    ?assertMatch({error, _}, Result).
