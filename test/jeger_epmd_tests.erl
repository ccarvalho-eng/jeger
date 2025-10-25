-module(jeger_epmd_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Tests
%%%===================================================================

check_epmd_localhost_test() ->
    %% Test EPMD check on localhost - should work if EPMD is running
    Result = jeger_epmd:check_epmd("localhost", 1000),
    ?assert(Result =:= {ok, available} orelse
            element(1, Result) =:= error).

check_epmd_invalid_host_test() ->
    %% Test EPMD check on invalid host - should fail
    Result = jeger_epmd:check_epmd("192.168.255.255", 100),
    ?assertMatch({error, _}, Result).

query_names_invalid_host_test() ->
    %% Test querying names on invalid host
    Result = jeger_epmd:query_names("192.168.255.255", 100),
    ?assertMatch({error, _}, Result).

query_port_invalid_host_test() ->
    %% Test querying port on invalid host
    Result = jeger_epmd:query_port("192.168.255.255", "testnode", 100),
    ?assertMatch({error, _}, Result).
