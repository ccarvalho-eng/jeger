-module(jeger_cluster_tests).

-include_lib("eunit/include/eunit.hrl").

scan_cluster_invalid_nodes_test_() ->
    {timeout, 60, fun() ->
        {ok, Result} = jeger_cluster:scan_cluster(
            "192.168.255.255",
            ["fake1", "fake2"],
            test_cookie,
            #{verbose => false}
        ),

        ?assertEqual(2, maps:get(scanned, Result)),
        ?assertEqual(0, maps:get(successful, Result)),

        Results = maps:get(results, Result),
        ?assertEqual(2, length(Results)),
        ?assert(lists:all(fun(#{status := S}) -> S =:= error end, Results))
    end}.

format_cluster_scan_test() ->
    MockResult = #{
        scanned => 3,
        successful => 3,
        summary => #{
            total_findings => 5,
            critical => 1,
            high => 2,
            medium => 2
        }
    },
    Output = jeger_cluster:format_cluster_scan(MockResult),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "Nodes Scanned: 3") > 0),
    ?assert(string:str(Output, "Critical: 1") > 0).

format_cluster_scan_no_findings_test() ->
    MockResult = #{
        scanned => 2,
        successful => 2,
        summary => #{
            total_findings => 0,
            critical => 0,
            high => 0,
            medium => 0
        }
    },
    Output = jeger_cluster:format_cluster_scan(MockResult),
    ?assert(string:str(Output, "Total Vulnerabilities: 0") > 0).