%%%-------------------------------------------------------------------
%%% @doc
%%% Distributed Erlang utilities for Jeger.
%%% Handles node initialization without corrupting global state.
%%% @end
%%%-------------------------------------------------------------------
-module(jeger_dist).

-export([
    ensure_distributed/1,
    with_cookie/2
]).

%% @doc Ensure distributed mode is started
-spec ensure_distributed(atom()) -> ok | {error, term()}.
ensure_distributed(Cookie) ->
    case node() of
        nonode@nohost ->
            NodeName = generate_node_name(),
            case net_kernel:start([NodeName, shortnames]) of
                {ok, _} ->
                    erlang:set_cookie(node(), Cookie),
                    ok;
                {error, {already_started, _}} ->
                    erlang:set_cookie(node(), Cookie),
                    ok;
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            erlang:set_cookie(node(), Cookie),
            ok
    end.

%% @doc Execute function with temporary cookie (best effort)
-spec with_cookie(atom(), fun(() -> Result)) -> Result.
with_cookie(Cookie, Fun) ->
    OldCookie = erlang:get_cookie(),
    try
        erlang:set_cookie(node(), Cookie),
        Fun()
    after
        erlang:set_cookie(node(), OldCookie)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

generate_node_name() ->
    Timestamp = erlang:system_time(millisecond),
    Rand = rand:uniform(99999),
    list_to_atom(lists:flatten(
        io_lib:format("jeger_~p_~p", [Timestamp, Rand])
    )).
