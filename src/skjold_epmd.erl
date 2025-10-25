%%%-------------------------------------------------------------------
%%% @doc
%%% EPMD (Erlang Port Mapper Daemon) protocol implementation.
%%% Used for discovering registered Erlang nodes on remote hosts.
%%%
%%% EPMD typically runs on port 4369 and maintains a registry of
%%% Erlang node names and their distribution ports.
%%% @end
%%%-------------------------------------------------------------------
-module(skjold_epmd).

-export([
    query_names/1,
    query_names/2,
    query_port/2,
    query_port/3,
    check_epmd/1,
    check_epmd/2
]).

-define(EPMD_PORT, 4369).
-define(DEFAULT_TIMEOUT, 5000).
-define(MAX_RESPONSE_SIZE, 1048576). % 1MB max response

%% EPMD protocol request types
-define(EPMD_NAMES_REQ, 110).      % 'n' - request for all registered names
-define(EPMD_PORT_PLEASE2_REQ, 122). % 'z' - request for specific node port

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Check if EPMD is running on the target host
-spec check_epmd(inet:ip_address() | string()) ->
    {ok, available} | {error, term()}.
check_epmd(Host) ->
    check_epmd(Host, ?DEFAULT_TIMEOUT).

-spec check_epmd(inet:ip_address() | string(), timeout()) ->
    {ok, available} | {error, term()}.
check_epmd(Host, Timeout) ->
    case gen_tcp:connect(Host, ?EPMD_PORT, [binary, {active, false}], Timeout) of
        {ok, Socket} ->
            gen_tcp:close(Socket),
            {ok, available};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Query EPMD for all registered node names
-spec query_names(inet:ip_address() | string()) ->
    {ok, [map()]} | {error, term()}.
query_names(Host) ->
    query_names(Host, ?DEFAULT_TIMEOUT).

-spec query_names(inet:ip_address() | string(), timeout()) ->
    {ok, [map()]} | {error, term()}.
query_names(Host, Timeout) ->
    case gen_tcp:connect(Host, ?EPMD_PORT, [binary, {active, false}], Timeout) of
        {ok, Socket} ->
            try
                Request = <<?EPMD_NAMES_REQ>>,
                case gen_tcp:send(Socket, Request) of
                    ok ->
                        receive_epmd_names(Socket, Timeout);
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                gen_tcp:close(Socket)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Query EPMD for a specific node's port
-spec query_port(inet:ip_address() | string(), string() | atom()) ->
    {ok, pos_integer()} | {error, term()}.
query_port(Host, NodeName) ->
    query_port(Host, NodeName, ?DEFAULT_TIMEOUT).

-spec query_port(inet:ip_address() | string(), string() | atom(), timeout()) ->
    {ok, pos_integer()} | {error, term()}.
query_port(Host, NodeName, Timeout) when is_atom(NodeName) ->
    query_port(Host, atom_to_list(NodeName), Timeout);
query_port(Host, NodeName, Timeout) ->
    case gen_tcp:connect(Host, ?EPMD_PORT, [binary, {active, false}], Timeout) of
        {ok, Socket} ->
            try
                NameBin = list_to_binary(NodeName),
                NameLen = byte_size(NameBin),
                Request = <<NameLen:16, ?EPMD_PORT_PLEASE2_REQ, NameBin/binary>>,
                case gen_tcp:send(Socket, Request) of
                    ok ->
                        receive_epmd_port(Socket, Timeout);
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                gen_tcp:close(Socket)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
%% Parse EPMD names response
receive_epmd_names(Socket, Timeout) ->
    case gen_tcp:recv(Socket, 0, Timeout) of
        {ok, Data} when byte_size(Data) =< ?MAX_RESPONSE_SIZE ->
            parse_names_response(Data);
        {ok, _Data} ->
            {error, response_too_large};
        {error, Reason} ->
            {error, Reason}
    end.

%% @private
%% Parse EPMD port response
receive_epmd_port(Socket, Timeout) ->
    case gen_tcp:recv(Socket, 0, Timeout) of
        {ok, <<0, Port:16, _Rest/binary>>} ->
            {ok, Port};
        {ok, <<Result, _Rest/binary>>} ->
            {error, {epmd_error, Result}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @private
%% Parse the EPMD names response into a list of node info maps
parse_names_response(<<_Port:32, Data/binary>>) ->
    Lines = binary:split(Data, <<"\n">>, [global, trim_all]),
    Nodes = lists:filtermap(fun parse_node_line/1, Lines),
    {ok, Nodes};
parse_names_response(_) ->
    {error, invalid_response}.

%% @private
%% Parse individual node line from EPMD response
%% Format: "name <nodename> at port <port>"
parse_node_line(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [<<"name">>, NodeName, <<"at">>, <<"port">>, PortBin | _] ->
            try binary_to_integer(PortBin) of
                Port ->
                    {true, #{
                        name => binary_to_list(NodeName),
                        port => Port,
                        raw => binary_to_list(Line)
                    }}
            catch
                _:_ -> false
            end;
        _ ->
            false
    end.
