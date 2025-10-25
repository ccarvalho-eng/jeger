-module(skjold_enum_tests).

-include_lib("eunit/include/eunit.hrl").

enumerate_node_invalid_test() ->
    %% Test enumeration on non-existent node
    Result = skjold_enum:enumerate_node("192.168.255.255", "fake", test_cookie),
    ?assertEqual({error, connection_failed}, Result).

format_enumeration_test() ->
    %% Test formatting enumeration results
    MockData = #{
        node => 'test@localhost',
        host => "localhost",
        otp_version => "24",
        system => "Erlang/OTP 24",
        applications => [{app1, "desc", "1.0"}],
        process_count => 100,
        security => #{cookie_visible => true, distribution_protocol => inet_tcp}
    },
    Output = skjold_enum:format_enumeration(MockData),
    ?assert(is_list(Output)),
    ?assert(string:str(Output, "test@localhost") > 0).
