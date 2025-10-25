%%%-------------------------------------------------------------------
%% @doc jeger public API
%% @end
%%%-------------------------------------------------------------------

-module(jeger_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    jeger_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
