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

-export([]).
-export_type([
    dh_fun/0,
    cipher_fun/0,
    hash_fun/0
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
    ss   :: symmetric(),
    dh   :: dh_fun(),
    role :: ini | rsp,
    hs   :: list(list(atom())),
    s    :: {binary() | nil, binary()},
    e    :: {binary() | nil, binary()},
    rs   :: nil | binary(),
    re   :: nil | binary(),
    buf  :: iodata()    
    }).

-include("vixen.hrl").

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
initialize_key(#cipher{k = undefined} = Cipher, <<Key:32/binary>>) ->
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
        ?_assertError(function_clause, initialize_key(initialize_key(Cipher, Key), Key))
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
