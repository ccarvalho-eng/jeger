-module(jeger_scan_tests).

-include_lib("eunit/include/eunit.hrl").

scan_node_invalid_test() ->
    Result = jeger_scan:scan_node("192.168.255.255", "fake", test_cookie),
    ?assertEqual({error, connection_failed}, Result).

format_findings_test() ->
    MockData = #{
        node => 'test@localhost',
        findings => [
            #{type => weak_cookie, severity => critical, description => "Weak cookie"}
        ]
    },
    Output = jeger_scan:format_findings(MockData),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "CRITICAL") > 0).

scan_vulnerabilities_test() ->
    MockEnum = #{
        node => 'test@localhost',
        security => #{
            cookie_visible => true,
            distribution_protocol => inet_tcp
        }
    },
    Result = jeger_scan:scan_vulnerabilities(MockEnum),
    ?assertMatch([{node, _}, {findings, _}], Result).

scan_vulnerabilities_cookie_exposed_test() ->
    MockEnum = #{
        node => 'test@localhost',
        security => #{
            cookie_visible => true,
            distribution_protocol => inet_tls
        }
    },
    [{node, _}, {findings, Findings}] = jeger_scan:scan_vulnerabilities(MockEnum),
    ?assert(length(Findings) > 0),
    ?assert(lists:any(fun(#{type := T}) -> T =:= cookie_exposed end, Findings)).

scan_vulnerabilities_unencrypted_dist_test() ->
    MockEnum = #{
        node => 'test@localhost',
        security => #{
            cookie_visible => false,
            distribution_protocol => inet_tcp
        }
    },
    [{node, _}, {findings, Findings}] = jeger_scan:scan_vulnerabilities(MockEnum),
    ?assert(lists:any(fun(#{type := T}) -> T =:= unencrypted_distribution end, Findings)).

scan_vulnerabilities_no_issues_test() ->
    MockEnum = #{
        node => 'test@localhost',
        security => #{
            cookie_visible => false,
            distribution_protocol => inet_tls
        }
    },
    [{node, _}, {findings, Findings}] = jeger_scan:scan_vulnerabilities(MockEnum),
    ?assertEqual([], Findings).

format_findings_with_high_severity_test() ->
    MockData = #{
        node => 'test@localhost',
        findings => [
            #{type => cookie_exposed, severity => high, description => "Cookie exposed"}
        ]
    },
    Output = jeger_scan:format_findings(MockData),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "HIGH") > 0).

format_findings_empty_test() ->
    MockData = #{
        node => 'test@localhost',
        findings => []
    },
    Output = jeger_scan:format_findings(MockData),
    ?assert(is_list(Output)).
