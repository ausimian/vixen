-module(vixen_test).

-include("../src/vixen.hrl").
-include_lib("eunit/include/eunit.hrl").

cacophony_test_() ->
    {ok, Content} = file:read_file("test/vectors/cacophony.json"),
    {ok, #{<<"vectors">> := Vectors}} = thoas:decode(Content),
    [{binary_to_list(Title), ?_test(test_vector(V))} || #{<<"protocol_name">> := Title} = V <- lists:sublist(Vectors, 540)].

test_vector(#{<<"protocol_name">> := Pn} = Vec) ->
    [<<"Noise">>, Pattern, Curve, Cipher, Hash] = binary:split(Pn, <<"_">>, [global]),
    Hs = binary_to_atom(Pattern),
    Dh = to_atom(Curve),
    Cf = to_atom(Cipher),
    Ha = to_atom(Hash),
    test_vector(Hs, Dh, Cf, Ha, Vec).

test_vector(Hs, _, _, _, _) when Hs =:= 'N'; Hs =:= 'K'; Hs =:= 'X' ->
    ok;
test_vector(Hs, Dh, Cf, Ha, Vec) ->
    IniPrologue  = binary:decode_hex(map_get(<<"init_prologue">>, Vec)),
    IniEphemeral = generate_key_pair(Dh, get_ephemeral(ini, Vec)),
    IniPsk       = get_psks(ini, Vec),
    IniStatic    = get_static(ini, Vec),
    IniRemote    = get_remote_static(ini, Vec),
    RspPrologue  = binary:decode_hex(map_get(<<"resp_prologue">>, Vec)),
    RspEphemeral = generate_key_pair(Dh, get_ephemeral(rsp, Vec)),
    RspPsk       = get_psks(rsp, Vec),
    RspStatic    = get_static(rsp, Vec),
    RspRemote    = get_remote_static(rsp, Vec),

    IniKeys = [{psk, IniPsk}, {s, generate_key_pair(Dh, IniStatic)}, {rs, IniRemote}, {e, IniEphemeral}, {psk, IniPsk}],
    Ini     = vixen:new(ini, Hs, Dh, Cf, Ha, IniKeys, [{prologue, IniPrologue}]),

    RspKeys = [{psk, RspPsk}, {s, generate_key_pair(Dh, RspStatic)}, {rs, RspRemote}, {e, RspEphemeral}, {psk, RspPsk}],
    Rsp     = vixen:new(rsp, Hs, Dh, Cf, Ha, RspKeys, [{prologue, RspPrologue}]),

    Msgs = map_get(<<"messages">>, Vec),
    run(Msgs, Ini, Rsp).

run([], _, _) ->
    ok;
run([Msg | Msgs], Ref1, Ref2) ->
    Payload    = binary:decode_hex(map_get(<<"payload">>, Msg)),
    CipherText = binary:decode_hex(map_get(<<"ciphertext">>, Msg)),
    {_, Encrypted} = vixen:write(Ref1, Payload),
    ?assertEqual(CipherText, iolist_to_binary(Encrypted)),
    vixen:read(Ref2, Encrypted),
    run(Msgs, Ref2, Ref1).

generate_key_pair(_Dh, undefined) -> undefined;
generate_key_pair(Dh, PrivateKey) -> crypto:generate_key(ecdh, Dh, PrivateKey).

get_ephemeral(ini, Vec) -> get_key(<<"init_ephemeral">>, Vec);
get_ephemeral(rsp, Vec) -> get_key(<<"resp_ephemeral">>, Vec).

get_psks(ini, Vec) -> get_keys(<<"init_psks">>, Vec);
get_psks(rsp, Vec) -> get_keys(<<"resp_psks">>, Vec).

get_static(ini, Vec) -> get_key(<<"init_static">>, Vec);
get_static(rsp, Vec) -> get_key(<<"resp_static">>, Vec).

get_remote_static(ini, Vec) -> get_key(<<"init_remote_static">>, Vec);
get_remote_static(rsp, Vec) -> get_key(<<"resp_remote_static">>, Vec).

get_key(K, M) when is_map_key(K, M) -> binary:decode_hex(map_get(K, M));
get_key(_, _) -> undefined.

get_keys(K, M) -> lists:map(fun binary:decode_hex/1, maps:get(K, M, [])).

to_atom(<<"25519">>) -> x25519;
to_atom(<<"448">>) -> x448;
to_atom(<<"ChaChaPoly">>) -> chacha20_poly1305;
to_atom(<<"AESGCM">>) -> aes_256_gcm;
to_atom(<<"SHA256">>) -> sha256;
to_atom(<<"SHA512">>) -> sha512;
to_atom(<<"BLAKE2s">>) -> blake2s;
to_atom(<<"BLAKE2b">>) -> blake2b.