-module(jeger_enum_tests).

-include_lib("eunit/include/eunit.hrl").

enumerate_node_invalid_test_() ->
    {timeout, 60, fun() ->
        Result = jeger_enum:enumerate_node("192.168.255.255", "fake", test_cookie),
        ?assertEqual({error, connection_failed}, Result)
    end}.

format_enumeration_test() ->
    MockData = #{
        node => 'test@localhost',
        host => "localhost",
        otp_version => "24",
        system => "Erlang/OTP 24",
        applications => [{app1, "desc", "1.0"}],
        process_count => 100,
        security => #{cookie_visible => true, distribution_protocol => inet_tcp}
    },
    Output = jeger_enum:format_enumeration(MockData),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "test@localhost") > 0).

format_enumeration_minimal_test() ->
    MockData = #{
        node => 'minimal@host'
    },
    Output = jeger_enum:format_enumeration(MockData),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "minimal@host") > 0).

format_enumeration_with_all_fields_test() ->
    MockData = #{
        node => 'full@localhost',
        host => "localhost",
        otp_version => "26",
        system => "Erlang/OTP 26",
        applications => [{app1, "desc1", "1.0"}, {app2, "desc2", "2.0"}],
        process_count => 500,
        security => #{cookie_visible => false, distribution_protocol => inet_tls}
    },
    Output = jeger_enum:format_enumeration(MockData),
    ?assert(string:str(Output, "full@localhost") > 0),
    ?assert(string:str(Output, "OTP Version") > 0),
    ?assert(string:str(Output, "Security") > 0).
