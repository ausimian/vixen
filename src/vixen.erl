%%%-----------------------------------------------------------------------------
%%% @doc
%%% Vixen - an implementation of the Noise Protocol
%%% @author ausimian
%%% @end
%%%-----------------------------------------------------------------------------
-module(vixen).
-author("ausimian").

-define(VSN, 1).
-vsn(?VSN).

-type dh_fun() :: x25519 | x448.
-type cipher_fun() :: chacha20_poly1305 | aes_256_gcm.
-type hash_fun() :: sha256 | sha512 | blake2s | blake2b.
-type role() :: ini | rsp.
-type public_key() :: binary().
-type private_key() :: binary().
-type key_pair() :: {public_key(), private_key()}.
-type key() :: {s, key_pair()} | {e, key_pair()} | {re, public_key()} | {rs, public_key()}.

-type token() :: e | s | ee | es | se | ss | psk.
-type message_pattern() :: {role(), [token()]} | {}.
-type handshake_pattern() :: [message_pattern()].

-type prologue_option() :: {prologue, binary()}.
-type option() :: prologue_option.

-export([
    new/5,
    new/6,
    new/7,
    write/1,
    write/2,
    read/2
]).
-export_type([
    dh_fun/0,
    cipher_fun/0,
    hash_fun/0,
    role/0,
    public_key/0,
    private_key/0,
    key_pair/0,
    key/0,
    token/0,
    message_pattern/0,
    handshake_pattern/0,
    prologue_option/0,
    option/0
    ]).

-record(cipher, {
    vsn :: pos_integer(),  
    cf  :: cipher_fun(),
    k  = undefined :: undefined | binary(),
    n  = 0 :: non_neg_integer()
    }).
-type cipher() :: #cipher{}.

-record(symmetric, {
    vsn :: pos_integer(),
    cs  :: cipher(),
    hf  :: hash_fun(),
    ck  :: binary(),
    h   :: binary()
    }).
-type symmetric() :: #symmetric{}.

-record(handshake, {
    vsn  :: pos_integer(),
    sym  :: symmetric(),
    dh   :: dh_fun(),
    role :: ini | rsp,
    hs   :: handshake_pattern(),
    s    :: undefined | key_pair(),
    e    :: undefined | key_pair(),
    rs   :: undefined | binary(),
    re   :: undefined | binary(),
    psk  :: undefined | binary(),
    buf  :: iodata()    
    }).
-type handshake() :: #handshake{}.

-include("vixen.hrl").

%%%=============================================================================
%%% Public functions
%%%=============================================================================
-spec new(Role :: role(), Hs :: atom(), Dh :: dh_fun(), Cf :: cipher_fun(), Hf :: hash_fun()) -> reference().
new(Role, Hs, Dh, Cf, Hf) ->
    new(Role, Hs, Dh, Cf, Hf, []).
-spec new(Role :: role(), Hs :: atom(), Dh :: dh_fun(), Cf :: cipher_fun(), Hf :: hash_fun(), Keys :: list(key())) -> reference().
new(Role, Hs, Dh, Cf, Hf, Keys) ->
    new(Role, Hs, Dh, Cf, Hf, Keys, []).
-spec new(Role :: role(), Hs :: atom(), Dh :: dh_fun(), Cf :: cipher_fun(), Hf :: hash_fun(), Keys :: list(key()), Opts :: list(option())) -> reference().
new(Role, Hs, Dh, Cf, Hf, Keys, Opts) ->
    Ref = make_ref(),
    put(Ref, handshake(Role, Hs, Dh, Cf, Hf, Keys, Opts)),
    Ref.

write(Ref) ->
    write(<<>>, Ref).
write(PlainText, Ref) ->
    case write_msg(get(Ref), PlainText) of
        {Hs, CryptText} ->
            put(Ref, Hs),
            CryptText;
        {Hs, CryptText, Result} ->
            put(Ref, Hs),
            {CryptText, Result}
    end.

read(Ref, CryptText) ->
    case read_msg(get(Ref), CryptText) of
        {Hs, PlainText} ->
            put(Ref, Hs),
            PlainText;
        {Hs, PlainText, Result} ->
            put(Ref, Hs),
            {PlainText, Result}
    end.

%%%=============================================================================
%%% Internal Functions - Handshake state
%%%=============================================================================

-spec handshake(Role :: role(), Hs :: atom(), Dh :: dh_fun(), Cf :: cipher_fun(), Hf :: hash_fun(), Keys :: list(key()), Opts :: list(option())) -> handshake().
handshake(Role, Hs, Dh, Cf, Hf, Keys, Opts) when Role =:= ini orelse Role =:= rsp ->
    Db = proplists:get_value(db, Opts, vixen_db),
    St = #handshake{
        vsn  = ?VSN, 
        sym  = mix_hash(symmetric(Hs, Dh, Cf, Hf), proplists:get_value(prologue, Opts, <<>>)),
        role = Role,
        dh   = Dh,
        hs   = modify(proplists:get_value(modifiers, Opts, []), Db:lookup(Hs)),
        s    = proplists:get_value(s, Keys),
        e    = proplists:get_value(e, Keys),
        rs   = proplists:get_value(rs, Keys),
        re   = proplists:get_value(re, Keys),
        psk  = proplists:get_value(psk, Keys),
        buf  = []},
    mix_premessage_public_keys(St).

modify([], Pats) ->
    Pats;
modify([{fallback, true} | Mods], [Pat | Pats]) ->
    NewPats = 
        case Pat of
            {ini, [e]} -> [Pat, {} | Pats];
            {ini, [s]} -> [Pat, {} | Pats];
            {ini, [e, s]} -> [Pat, {} | Pats]
        end,
    modify(Mods, NewPats);
modify([{fallback, false} | Mods], Pats) ->
    modify(Mods, Pats).

-spec mix_premessage_public_keys(St :: handshake()) -> handshake().
mix_premessage_public_keys(#handshake{hs = Hs} = St) ->
    case string:str(Hs, [?SEP]) of
        0 -> St;
        N -> mix_premessage_public_keys(lists:sublist(Hs, N - 1), St#handshake{hs = lists:nthtail(N, Hs)})
    end.

-spec mix_premessage_public_keys([message_pattern()], St :: handshake()) -> handshake().
mix_premessage_public_keys([], St) -> St;
mix_premessage_public_keys([{_, []} | Msgs], St) ->
    mix_premessage_public_keys(Msgs, St);
mix_premessage_public_keys([{Role, [s | Keys]} | Msgs], #handshake{role = Role, s = {Public, _}, sym = Sym} = St) ->
    mix_premessage_public_keys([{Role, Keys} | Msgs], St#handshake{sym = mix_hash(Sym, Public)});
mix_premessage_public_keys([{Role, [s | Keys]} | Msgs], #handshake{rs = Public, sym = Sym} = St) ->
    mix_premessage_public_keys([{Role, Keys} | Msgs], St#handshake{sym = mix_hash(Sym, Public)});
mix_premessage_public_keys([{Role, [e | Keys]} | Msgs], #handshake{role = Role, e = {Public, _}, sym = Sym} = St) ->
    mix_premessage_public_keys([{Role, Keys} | Msgs], St#handshake{sym = mix_hash(Sym, Public)});
mix_premessage_public_keys([{Role, [e | Keys]} | Msgs], #handshake{re = Public, sym = Sym} = St) ->
    mix_premessage_public_keys([{Role, Keys} | Msgs], St#handshake{sym = mix_hash(Sym, Public)}).

-spec write_msg(Hs :: handshake(), Msg :: iodata()) -> {binary(), handshake()} | {binary(), cipher(), cipher()}.
write_msg(#handshake{hs = [{_, Tokens} | Pats]} = St, Msg) ->
    St1 = #handshake{sym = Sym, buf = Buf} = lists:foldl(fun write_step/2, St#handshake{hs = Pats}, Tokens),
    {NewSym, Crypt} = encrypt_and_hash(Sym, Msg),
    maybe_split(St1#handshake{sym = NewSym, buf = [Buf, Crypt]}).

-spec read_msg(Hs :: handshake(), Msg :: iodata()) -> {binary(), handshake()} | {binary(), cipher(), cipher()}.
read_msg(#handshake{hs = [{_, Tokens} | Pats]} = St, Msg) ->
    St1 = #handshake{sym = Sym, buf = Buf } = lists:foldl(fun read_step/2, St#handshake{hs = Pats, buf = iolist_to_binary(Msg)}, Tokens),
    {NewSym, Plain} = decrypt_and_hash(Sym, Buf),
    maybe_split(St1#handshake{sym = NewSym, buf = Plain}).

-spec write_step(token(), handshake()) -> handshake().
write_step(e, #handshake{e = undefined, dh = Dh, sym = Sym, buf = Buf} = St) ->
    {EPub, _} = E = vixen_crypto:generate_keypair(Dh),
    St#handshake{e = E, buf = [Buf, EPub], sym = mix_hash(Sym, EPub)};
write_step(s, #handshake{buf = Buf, sym = Sym, s = {SPub, _}} = St) ->
    {NewSym, Crypt} = encrypt_and_hash(Sym, SPub),
    St#handshake{buf = [Buf, Crypt], sym = NewSym};
write_step(psk, #handshake{sym = Sym, psk = Psk, e = {Public, _}} = St) ->
    St#handshake{sym = mix_key(mix_key_and_hash(Sym, Psk), Public)};
write_step(Tok, St) ->
    common_step(Tok, St).

-spec read_step(token(), handshake()) -> handshake().
read_step(e, #handshake{dh = Dh, re = undefined, buf = Buf, sym = Sym} = St) ->
    {Re, Rest} = split_binary(Buf, vixen_crypto:dh_len(Dh)),
    St#handshake{buf = Rest, re = Re, sym = mix_hash(Sym, Re)};
read_step(s, #handshake{dh = Dh, rs = undefined, buf = Buf, sym = Sym} = St) ->
    KeyLen = vixen_crypto:dh_len(Dh) + (case has_key(Sym) of true -> 16; false -> 0 end),
    {Temp, Rest} = split_binary(Buf, KeyLen),
    {NewSym, Plain} = decrypt_and_hash(Sym, Temp),
    St#handshake{buf = Rest, rs = Plain, sym = NewSym};
read_step(psk, #handshake{sym = Sym, psk = Psk, re = Public} = St) ->
    St#handshake{sym = mix_key(mix_key_and_hash(Sym, Psk), Public)};
read_step(Tok, St) ->
    common_step(Tok, St).

-spec common_step(token(), handshake()) -> handshake().
common_step(ee, #handshake{sym = Sym, dh = Dh, e = E, re = Re} = St) ->
    St#handshake{sym = mix_key(Sym, vixen_crypto:dh(Dh, E, Re))};
common_step(es, #handshake{role = ini, sym = Sym, dh = Dh, e = E, rs = Rs} = St) ->
    St#handshake{sym = mix_key(Sym, vixen_crypto:dh(Dh, E, Rs))};
common_step(es, #handshake{role = rsp, sym = Sym, dh = Dh, s = S, re = Re} = St) ->
    St#handshake{sym = mix_key(Sym, vixen_crypto:dh(Dh, S, Re))};
common_step(se, #handshake{role = ini, sym = Sym, dh = Dh, s = S, re = Re} = St) ->
    St#handshake{sym = mix_key(Sym, vixen_crypto:dh(Dh, S, Re))};
common_step(se, #handshake{role = rsp, sym = Sym, dh = Dh, e = E, rs = Rs} = St) ->
    St#handshake{sym = mix_key(Sym, vixen_crypto:dh(Dh, E, Rs))};
common_step(ss, #handshake{sym = Sym, dh = Dh, s = S, rs = Rs} = St) ->
    St#handshake{sym = mix_key(Sym, vixen_crypto:dh(Dh, S, Rs))}.

maybe_split(#handshake{role = Role, buf = Buf, hs = [], sym = Sym} = Hs) ->
    {Hs#handshake{buf = []}, Buf, swap(Role, split(Sym))};
maybe_split(#handshake{buf = Buf} = Hs) ->
    {Hs#handshake{buf = []}, Buf}.

swap(ini, {X,Y}) -> {X,Y};
swap(rsp, {X,Y}) -> {Y,X}.

%%%=============================================================================
%%% Internal Functions - Symmetric state
%%%=============================================================================
-spec symmetric(Hs :: atom(), Dh :: dh_fun(), Cf :: cipher_fun(), Hf :: hash_fun()) -> symmetric().
symmetric(Hs, Dh, Cf, Hf) ->
    ProtocolName = [
        "Noise", "_",
        atom_to_binary(Hs), "_",
        to_string(Dh), "_",
        to_string(Cf), "_",
        to_string(Hf)
    ],
    Hash = 
        case vixen_crypto:hash_len(Hf) - iolist_size(ProtocolName) of
            N when N >= 0 -> iolist_to_binary([ProtocolName, <<0:(N*8)>>]);
            _ -> vixen_crypto:hash(Hf, ProtocolName)
        end,
    #symmetric{vsn = ?VSN, cs = cipher(Cf), hf = Hf, ck = Hash, h = Hash}.

mix_key(#symmetric{cs = Cs, hf = Hf, ck = Ck} = Sym, Ikm) ->
    {NewCk, <<Tk:32/binary, _/binary>>} = vixen_crypto:hkdf(Hf, Ck, Ikm, 2),
    Sym#symmetric{ck = NewCk, cs = initialize_key(Cs, Tk)}.

mix_hash(#symmetric{hf = Hf, h = Hash} = Sym, Data) ->
    Sym#symmetric{h = mix_hash(Hf, Hash, Data)}.

mix_hash(Hf, Hash, Data) ->
    vixen_crypto:hash(Hf, [Hash, Data]).

mix_key_and_hash(#symmetric{hf = Hf, h = Hash, ck = Ck, cs = Cs} = Sym, Ikm) ->
    {NewCk, TempHash, <<TempKey:32/binary, _/binary>>} = vixen_crypto:hkdf(Hf, Ck, Ikm, 3),
    Sym#symmetric{ck = NewCk, h = mix_hash(Hf, Hash, TempHash), cs = initialize_key(Cs, TempKey)}.

get_handshake_hash(#symmetric{h = Hash}) -> Hash.

encrypt_and_hash(#symmetric{cs = Cs, hf = Hf, h = Hash} = Sym, PlainText) ->
    {NewCs, CryptText} = encrypt_with_aad(Cs, Hash, PlainText),
    {Sym#symmetric{h = mix_hash(Hf, Hash, CryptText), cs = NewCs}, CryptText}.

decrypt_and_hash(#symmetric{cs = Cs, hf = Hf, h = Hash} = Sym, CryptText) ->
    {NewCs, PlainText} = decrypt_with_aad(Cs, Hash, CryptText),
    {Sym#symmetric{h = mix_hash(Hf, Hash, CryptText), cs = NewCs}, PlainText}.

split(#symmetric{hf = Hf, ck = Ck, cs = Cs}) ->
    {<<K1:32/binary, _/binary>>, <<K2:32/binary, _/binary>>} = vixen_crypto:hkdf(Hf, Ck, <<>>, 2),
    split(Cs, K1, K2).

-spec has_key(symmetric() | cipher()) -> boolean().
has_key(#symmetric{cs = Cs}) -> has_key(Cs);
has_key(#cipher{k = <<_:32/binary>>}) -> true;
has_key(#cipher{k = undefined}) -> false.

to_string(x25519) -> "25519";
to_string(x448) -> "448";
to_string(chacha20_poly1305) -> "ChaChaPoly";
to_string(aes_256_gcm) -> "AESGCM";
to_string(sha256) -> "SHA256";
to_string(sha512) -> "SHA512";
to_string(blake2s) -> "BLAKE2s";
to_string(blake2b) -> "BLAKE2b".

%%%=============================================================================
%%% Internal Functions - Cipher state
%%%=============================================================================

-spec cipher(Cf :: cipher_fun()) -> cipher().
cipher(Cf) when Cf =:= chacha20_poly1305 orelse Cf =:= aes_256_gcm ->
    #cipher{vsn = ?VSN, cf = Cf, k = undefined, n = 0}.

-spec initialize_key(Cipher :: cipher(), Key :: binary()) -> cipher().
initialize_key(#cipher{} = Cipher, <<Key:32/binary>>) ->
    Cipher#cipher{k = Key, n = 0}.


-spec rekey(Cipher :: cipher()) -> cipher().
rekey(#cipher{cf = Cf, k = Key} = Cipher) ->
    Cipher#cipher{k = vixen_crypto:rekey(Cf, Key)}.

-spec set_nonce(Cipher :: cipher(), Nonce :: non_neg_integer()) -> cipher().
set_nonce(#cipher{} = Cipher, Nonce) when is_integer(Nonce) andalso Nonce >= 0 ->
    Cipher#cipher{n = Nonce}.

-spec encrypt_with_aad(Cipher :: cipher(), AAD :: iodata(), PlainText :: iodata()) -> {cipher(), iodata()}.
encrypt_with_aad(#cipher{k = undefined} = Cipher, _AAD, PlainText) ->
    {Cipher, PlainText};
encrypt_with_aad(#cipher{cf = Cf, k = Key, n = N} = Cipher, AAD, PlainText) when N < ?REKEY_NONCE ->
    {Cipher#cipher{n = N + 1},  tuple_to_list(vixen_crypto:encrypt(Cf, Key, N, AAD, PlainText))}.

-spec decrypt_with_aad(Cipher :: cipher(), AAD :: iodata(), CryptText :: iodata()) -> {cipher(), iodata()}.
decrypt_with_aad(#cipher{k = undefined} = Cipher, _AAD, CryptText) ->
    {Cipher, CryptText};
decrypt_with_aad(#cipher{cf = Cf, k = Key, n = N} = Cipher, AAD, CryptText) when N < ?REKEY_NONCE ->
    {Cipher#cipher{n = N + 1}, vixen_crypto:decrypt(Cf, Key, N, AAD, CryptText)}.

split(#cipher{cf = Cf}, K1, K2) ->
    Cipher = cipher(Cf),
    {initialize_key(Cipher, K1), initialize_key(Cipher, K2)}.



%%%=============================================================================
%%% Eunit Tests 
%%%=============================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

-define(CURVES, [x25519, x448]).
-define(CIPHERS, [chacha20_poly1305, aes_256_gcm]).
-define(HASHES, [sha256, sha512, blake2s, blake2b]).

%%%-----------------------------------------------------------------------------
%%% Handshake State Tests 
%%%-----------------------------------------------------------------------------
handshake_NN_test() ->
    Ini1 = handshake(ini, 'NN', x25519, chacha20_poly1305, sha256, [], []),
    Rsp1 = handshake(rsp, 'NN', x25519, chacha20_poly1305, sha256, [], []),

    {Ini2, Out1} = write_msg(Ini1, <<>>),
    {Rsp2, <<>>} = read_msg(Rsp1, Out1),

    {_Rsp3, Out2, {RspIn, _RspOut}} = write_msg(Rsp2, <<>>),
    {_Ini3, <<>>, {_IniIn, IniOut}} = read_msg(Ini2, Out2),

    Msg = crypto:strong_rand_bytes(1024),
    Aad = crypto:strong_rand_bytes(32),

    {_, MsgX} = encrypt_with_aad(IniOut, Aad, Msg),
    {_, Msg} = decrypt_with_aad(RspIn, Aad, MsgX).

handshake_XX_test() ->
    IniPair = crypto:generate_key(ecdh, x25519),
    RspPair = crypto:generate_key(ecdh, x25519),

    Ini1 = handshake(ini, 'XX', x25519, chacha20_poly1305, sha256, [{s, IniPair}], []),
    Rsp1 = handshake(rsp, 'XX', x25519, chacha20_poly1305, sha256, [{s, RspPair}], []),

    {Ini2, Out1} = write_msg(Ini1, <<>>),
    {Rsp2, <<>>} = read_msg(Rsp1, Out1),

    {Rsp3, Out2} = write_msg(Rsp2, <<>>),
    {Ini3, <<>>} = read_msg(Ini2, Out2),

    {_Ini4, Out3, {_IniIn, IniOut}} = write_msg(Ini3, <<>>),
    {_Rsp4, <<>>, {RspIn, _RspOut}} = read_msg(Rsp3, Out3),

    Msg = crypto:strong_rand_bytes(1024),
    Aad = crypto:strong_rand_bytes(32),

    {_, MsgX} = encrypt_with_aad(IniOut, Aad, Msg),
    {_, Msg} = decrypt_with_aad(RspIn, Aad, MsgX).

handshake_XXFallback_test() ->
    StaticIniPair = crypto:generate_key(ecdh, x25519),
    StaticRspPair = crypto:generate_key(ecdh, x25519),
    {EphemeralIniPub, _} = EphemeralIniPair = crypto:generate_key(ecdh, x25519),

    Mods = [{fallback, true}],
    Ini1 = handshake(ini, 'XX', x25519, chacha20_poly1305, sha256, [{s, StaticIniPair}, {e, EphemeralIniPair}], [{modifiers, Mods}]),
    Rsp1 = handshake(rsp, 'XX', x25519, chacha20_poly1305, sha256, [{s, StaticRspPair}, {re, EphemeralIniPub}], [{modifiers, Mods}]),

    {Rsp2, Out1} = write_msg(Rsp1, <<>>),
    {Ini2, <<>>} = read_msg(Ini1, Out1),

    {_Ini3, Out2, {_IniIn, IniOut}} = write_msg(Ini2, <<>>),
    {_Rsp3, <<>>, {RspIn, _RspOut}} = read_msg(Rsp2, Out2),

    Msg = crypto:strong_rand_bytes(1024),
    Aad = crypto:strong_rand_bytes(32),

    {_, MsgX} = encrypt_with_aad(IniOut, Aad, Msg),
    {_, Msg} = decrypt_with_aad(RspIn, Aad, MsgX).

handshake_KK_test() ->
    {IniPub, _IniPriv} = IniPair = crypto:generate_key(ecdh, x25519),
    {RspPub, _RspPriv} = RspPair = crypto:generate_key(ecdh, x25519),

    Ini1 = handshake(ini, 'KK', x25519, chacha20_poly1305, sha256, [{s, IniPair}, {rs, RspPub}], []),
    Rsp1 = handshake(rsp, 'KK', x25519, chacha20_poly1305, sha256, [{s, RspPair}, {rs, IniPub}], []),

    {Ini2, Out1} = write_msg(Ini1, <<>>),
    {Rsp2, <<>>} = read_msg(Rsp1, Out1),

    {_Rsp3, Out2, {RspIn, _RspOut}} = write_msg(Rsp2, <<>>),
    {_Ini3, <<>>, {_IniIn, IniOut}} = read_msg(Ini2, Out2),

    Msg = crypto:strong_rand_bytes(1024),
    Aad = crypto:strong_rand_bytes(32),

    {_, MsgX} = encrypt_with_aad(IniOut, Aad, Msg),
    {_, Msg} = decrypt_with_aad(RspIn, Aad, MsgX).

%%%-----------------------------------------------------------------------------
%%% Symmetric State Tests 
%%%-----------------------------------------------------------------------------

symmetric_test_() -> [ 
    ?_test(symmetric('KK', Curve, Cipher, Hash)) 
    || Curve <- ?CURVES, Cipher <- ?CIPHERS, Hash <- ?HASHES ].

symmetric_encrypt_decrypt_test_() -> [ 
    ?_test(?LET(S,symmetric('KK', Curve, Cipher, Hash),symmetric_encrypt_decrypt(S, S)))
    || Curve <- ?CURVES, Cipher <- ?CIPHERS, Hash <- ?HASHES ].

symmetric_mix_key_test_() -> [
    ?_test(?LET(S,symmetric('KK', Curve, Cipher, Hash),
    begin
        ?assertNot(has_key(S)),
        S1 = mix_key(S, <<"fmdsalkfj90345ugskdfjfds49">>),
        ?assert(has_key(S1))
    end))
    || Curve <- ?CURVES, Cipher <- ?CIPHERS, Hash <- ?HASHES ].
        
symmetric_encrypt_decrypt(S1_1, S2_1) ->
    Data = crypto:strong_rand_bytes(32),
    S1_2 = mix_key_and_hash(mix_hash(S1_1, Data), Data),
    S2_2 = mix_key_and_hash(mix_hash(S2_1, Data), Data),
    PlainText = crypto:strong_rand_bytes(1024),
    {S1_3, CryptText} = encrypt_and_hash(S1_2, PlainText),
    {S2_3, PlainText2} = decrypt_and_hash(S2_2, CryptText),
    ?assertEqual(PlainText, PlainText2),
    {S1_4, CryptText2} = encrypt_and_hash(S1_3, PlainText),
    ?assertNotEqual(CryptText, CryptText2),
    {S2_4, PlainText3} = decrypt_and_hash(S2_3, CryptText2),
    ?assertEqual(PlainText, PlainText3),
    % Check internal state matches
    ?assertEqual(get_handshake_hash(S1_4), get_handshake_hash(S2_4)),
    ?assertEqual(split(S1_4), split(S2_4)).

%%%-----------------------------------------------------------------------------
%%% Cipher State Tests 
%%%-----------------------------------------------------------------------------

cipher_test_() -> [ ?_test(cipher(Cipher)) || Cipher <- ?CIPHERS ].

initialize_key_test_() -> [{
    setup,
    fun () -> {cipher(CipherFun), crypto:strong_rand_bytes(32)} end,
    fun ({Cipher, Key}) -> [
        ?_test(initialize_key(Cipher, Key)),
        ?_test(initialize_key(initialize_key(Cipher, Key), Key))
    ] end
    } || CipherFun <- ?CIPHERS].

has_key_test_() -> [{
    setup,
    fun () -> {cipher(CipherFun), crypto:strong_rand_bytes(32)} end,
    fun ({Cipher, Key}) -> [
        ?_assertNot(has_key(Cipher)),
        ?_assert(has_key(initialize_key(Cipher, Key)))
        ] end
    } || CipherFun <- ?CIPHERS].

rekey_test_() -> [{
    setup,
    fun () -> initialize_key(cipher(CipherFun), crypto:strong_rand_bytes(32)) end,
    fun (Cipher) -> [
        ?_assert(has_key(Cipher)),
        ?_assert(has_key(rekey(Cipher)))
        ] end
    } || CipherFun <- ?CIPHERS].

rekey_no_key_test_() -> [
    ?_assertError(function_clause, rekey(cipher(Cipher)))
    || Cipher <- ?CIPHERS
    ].

set_nonce_test_() -> [{
    setup,
    fun () -> cipher(CipherFun) end,
    fun (Cipher) -> [
        ?_assert(set_nonce(Cipher, 42) == set_nonce(Cipher, 42)),
        ?_assertNot(Cipher == set_nonce(Cipher, 42))
        ] end
    } || CipherFun <- ?CIPHERS].

encrypt_no_key_test_() -> [{
    setup,
    fun () -> {cipher(CipherFun), crypto:strong_rand_bytes(1024)} end,
    fun ({Cipher, PlainText}) -> [
        ?_assertMatch({Cipher, PlainText}, encrypt_with_aad(Cipher, <<>>, PlainText))
    ] end
    } || CipherFun <- ?CIPHERS].

encrypt_decrypt_test_() -> [{
    setup,
    fun () -> 
        Key = crypto:strong_rand_bytes(32),
        C1  = initialize_key(cipher(CipherFun), Key),
        C2  = initialize_key(cipher(CipherFun), Key),
        {C1, C2}
        end,
    fun ({C1, C2}) -> [?_test(cipher_encrypt_decrypt(C1, C2))] end
    } || CipherFun <- ?CIPHERS].

decrypt_no_key_test_() -> [{
    setup,
    fun () -> {cipher(CipherFun), crypto:strong_rand_bytes(1024)} end,
    fun ({Cipher, PlainText}) -> [
        ?_assertMatch({Cipher, PlainText}, decrypt_with_aad(Cipher, <<>>, PlainText))
    ] end
    } || CipherFun <- ?CIPHERS].

cipher_encrypt_decrypt(C1_1, C2_1) ->
    PlainText = crypto:strong_rand_bytes(1024),
    AAD = crypto:strong_rand_bytes(32),
    {C1_2, CryptText} = encrypt_with_aad(C1_1, AAD, PlainText),
    ?assertNotEqual(PlainText, CryptText),
    {C2_2, DecryptText} = decrypt_with_aad(C2_1, AAD, CryptText),
    ?assertEqual(PlainText, DecryptText),
    % Check nonce is incrementing
    {_, CryptText2} = encrypt_with_aad(C1_2, AAD, PlainText),
    ?assertNotEqual(CryptText2, CryptText),
    {_, DecryptText2} = decrypt_with_aad(C2_2, AAD, CryptText2),
    ?assertEqual(PlainText, DecryptText2).

-endif. % TEST
