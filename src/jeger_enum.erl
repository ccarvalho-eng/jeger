%%%-------------------------------------------------------------------
%%% @doc
%%% Node enumeration and fingerprinting for Jeger.
%%% Gathers system information from discovered Erlang nodes.
%%% @end
%%%-------------------------------------------------------------------
-module(jeger_enum).

-export([
    enumerate_node/3,
    enumerate_nodes/2,
    format_enumeration/1
]).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Enumerate a single node
-spec enumerate_node(string(), string(), atom()) ->
    {ok, map()} | {error, term()}.
enumerate_node(Host, NodeName, Cookie) ->
    TargetNode = list_to_atom(NodeName ++ "@" ++ Host),

    %% Start distributed if needed
    NameType = detect_name_type(Host),
    ensure_distributed(Cookie, NameType),

    %% Attempt connection
    case net_adm:ping(TargetNode) of
        pong ->
            Info = gather_info(TargetNode),
            {ok, Info#{node => TargetNode, host => Host}};
        pang ->
            {error, connection_failed}
    end.

%% @doc Enumerate multiple nodes concurrently
-spec enumerate_nodes([{string(), string()}], atom()) ->
    {ok, [map()]}.
enumerate_nodes(Targets, Cookie) ->
    ensure_distributed(Cookie, shortnames),
    Parent = self(),

    lists:foreach(fun({Host, NodeName}) ->
        spawn(fun() ->
            Result = enumerate_node(Host, NodeName, Cookie),
            Parent ! {enum_result, Result}
        end)
    end, Targets),

    collect_results(length(Targets), []).

%% @doc Format enumeration results
-spec format_enumeration(map()) -> string().
format_enumeration(#{node := Node} = Info) ->
    lists:flatten([
        io_lib:format("~n[+] Node: ~p~n", [Node]),
        format_field("OTP Version", maps:get(otp_version, Info, unknown)),
        format_field("System", maps:get(system, Info, unknown)),
        format_field("Applications", format_apps(maps:get(applications, Info, []))),
        format_field("Processes", maps:get(process_count, Info, 0)),
        format_field("Security", format_security(maps:get(security, Info, #{})))
    ]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

detect_name_type(Host) ->
    case string:find(Host, ".") of
        nomatch ->
            case lists:member($., Host) of
                false -> shortnames;
                true -> longnames
            end;
        _ -> longnames
    end.

ensure_distributed(Cookie, NameType) ->
    case node() of
        nonode@nohost ->
            ScannerNode = generate_node_name(NameType),
            net_kernel:start([ScannerNode, NameType]),
            erlang:set_cookie(node(), Cookie);
        _ ->
            erlang:set_cookie(node(), Cookie)
    end.

generate_node_name(shortnames) ->
    Rand = rand:uniform(99999),
    list_to_atom("jeger_enum_" ++ integer_to_list(Rand));
generate_node_name(longnames) ->
    Rand = rand:uniform(99999),
    {ok, Hostname} = inet:gethostname(),
    list_to_atom("jeger_enum_" ++ integer_to_list(Rand) ++ "@" ++ Hostname).

gather_info(TargetNode) ->
    #{
        otp_version => safe_rpc(TargetNode, erlang, system_info, [otp_release]),
        system => safe_rpc(TargetNode, erlang, system_info, [system_version]),
        applications => safe_rpc(TargetNode, application, which_applications, []),
        process_count => safe_rpc(TargetNode, erlang, system_info, [process_count]),
        security => gather_security_info(TargetNode)
    }.

gather_security_info(TargetNode) ->
    #{
        cookie_visible => check_cookie_visible(TargetNode),
        distribution_protocol => safe_rpc(TargetNode, net_kernel, protocol, [])
    }.

check_cookie_visible(TargetNode) ->
    case safe_rpc(TargetNode, erlang, get_cookie, []) of
        {badrpc, _} -> unknown;
        Cookie -> Cookie =/= nocookie
    end.

safe_rpc(Node, Module, Function, Args) ->
    case rpc:call(Node, Module, Function, Args, 5000) of
        {badrpc, Reason} -> {error, Reason};
        Result -> Result
    end.

collect_results(0, Acc) -> {ok, lists:reverse(Acc)};
collect_results(N, Acc) ->
    receive
        {enum_result, {ok, Result}} ->
            collect_results(N - 1, [Result | Acc]);
        {enum_result, {error, _}} ->
            collect_results(N - 1, Acc)
    after
        10000 -> {ok, lists:reverse(Acc)}
    end.

format_field(Label, Value) ->
    io_lib:format("  ~s: ~p~n", [Label, Value]).

format_apps(Apps) when is_list(Apps) ->
    length(Apps);
format_apps(_) ->
    unknown.

format_security(#{cookie_visible := Visible, distribution_protocol := Proto}) ->
    io_lib:format("cookie_visible=~p, protocol=~p", [Visible, Proto]);
format_security(_) ->
    "unknown".
