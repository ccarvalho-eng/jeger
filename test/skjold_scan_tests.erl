-module(skjold_scan_tests).

-include_lib("eunit/include/eunit.hrl").

scan_node_invalid_test() ->
    Result = skjold_scan:scan_node("192.168.255.255", "fake", test_cookie),
    ?assertEqual({error, connection_failed}, Result).

format_findings_test() ->
    MockData = #{
        node => 'test@localhost',
        findings => [
            #{type => weak_cookie, severity => critical, description => "Weak cookie"}
        ]
    },
    Output = skjold_scan:format_findings(MockData),
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
    Result = skjold_scan:scan_vulnerabilities(MockEnum),
    ?assertMatch([{node, _}, {findings, _}], Result).
