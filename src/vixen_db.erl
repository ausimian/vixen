%%%-----------------------------------------------------------------------------
%%% @doc
%%% Handshake database
%%% @author ausimian
%%% @end
%%%-----------------------------------------------------------------------------

-module(vixen_db).
-author("ausimian").

-include("vixen.hrl").

%%%=============================================================================
%%% Export and Defs
%%%=============================================================================

%% External API
-export([
    lookup/1
]).

%%%=============================================================================
%%% API
%%%=============================================================================
-spec lookup(atom()) -> vixen:handshake_pattern().
lookup('NN') -> [
    {ini, [e]},
    {rsp, [e, ee]}
];
lookup('KN') -> [
    {ini, [s]},
    ?SEP,
    {ini, [e]},
    {rsp, [e, ee, se]}
];
lookup('NK') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es]},
    {rsp, [e, ee]}
];
lookup('KK') -> [
    {ini, [s]},
    {rsp, [s]},
    ?SEP,
    {ini, [e, es, ss]},
    {rsp, [e, ee, se]}
];
lookup('NX') -> [
    {ini, [e]},
    {rsp, [e, ee, s, es]}
];
lookup('KX') -> [
    {ini, [s]},
    ?SEP,
    {ini, [e]},
    {rsp, [e, ee, se, s, es]}
];
lookup('XN') -> [
    {ini, [e]},
    {rsp, [e, ee]},
    {ini, [s, se]}
];
lookup('IN') -> [
    {ini, [e, s]},
    {rsp, [e, ee, se]}
];
lookup('XK') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es]},
    {rsp, [e, ee]},
    {ini, [s, se]}
];
lookup('IK') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es, s, ss]},
    {rsp, [e, ee, se]}
];
lookup('IX') -> [
    {ini, [e, s]},
    {rsp, [e, ee, se, s, es]}
];
lookup('XX') -> [
    {ini, [e]},
    {rsp, [e, ee, s, es]},
    {ini, [s, se]}
];

lookup('NNpsk0') -> [
    {ini, [psk, e]},
    {rsp, [e, ee]}
];
lookup('NNpsk2') -> [
    {ini, [e]},
    {rsp, [e, ee, psk]}
];
lookup('NKpsk0') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [psk, e, es]},
    {rsp, [e, ee]}
];
lookup('NKpsk2') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es]},
    {rsp, [e, ee, psk]}
];
lookup('NXpsk2') -> [
    {ini, [e]},
    {rsp, [e, ee, s, es, psk]}
];
lookup('XNpsk3') -> [
    {ini, [e]},
    {rsp, [e, ee]},
    {ini, [s, se, psk]}
];
lookup('XKpsk3') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es]},
    {rsp, [e, ee]},
    {ini, [s, se, psk]}
];
lookup('XXpsk3') -> [
    {ini, [e]},
    {rsp, [e, ee, s, es]},
    {ini, [s, se, psk]}
];
lookup('KNpsk0') -> [
    {ini, [s]},
    ?SEP,
    {ini, [psk, e]},
    {rsp, [e, ee, se]}
];
lookup('KNpsk2') -> [
    {ini, [s]},
    ?SEP,
    {ini, [e]},
    {rsp, [e, ee, se, psk]}
];
lookup('KKpsk0') -> [
    {ini, [s]},
    {rsp, [s]},
    ?SEP,
    {ini, [psk, e, es, ss]},
    {rsp, [e, ee, se]}
];
lookup('KKpsk2') -> [
    {ini, [s]},
    {rsp, [s]},
    ?SEP,
    {ini, [e, es, ss]},
    {rsp, [e, ee, se, psk]}
];
lookup('KXpsk2') -> [
    {ini, [s]},
    ?SEP,
    {ini, [e]},
    {rsp, [e, ee, se, s, es, psk]}
];
lookup('INpsk1') -> [
    {ini, [e, s, psk]},
    {rsp, [e, ee, se]}
];
lookup('INpsk2') -> [
    {ini, [e, s]},
    {rsp, [e, ee, se, psk]}
];
lookup('IKpsk1') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es, s, ss, psk]},
    {rsp, [e, ee, se]}
];
lookup('IKpsk2') -> [
    {rsp, [s]},
    ?SEP,
    {ini, [e, es, s, ss]},
    {rsp, [e, ee, se, psk]}
];
lookup('IXpsk2') -> [
    {ini, [e, s]},
    {rsp, [e, ee, se, s, es, psk]}
];

lookup(banana) -> [].
