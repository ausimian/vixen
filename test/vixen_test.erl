-module(vixen_test).

-include("../src/vixen.hrl").
-include_lib("eunit/include/eunit.hrl").

cacophony_test_() ->
    {ok, Content} = file:read_file("test/vectors/cacophony.json"),
    {ok, #{<<"vectors">> := Vectors}} = thoas:decode(Content),
    [{binary_to_list(Title), ?_test(test_vector(V))} || #{<<"name">> := Title} = V <- lists:sublist(Vectors, 16)].


test_vector(Vec) ->
    Hs = binary_to_atom(map_get(<<"pattern">>, Vec)),
    Dh = to_atom(map_get(<<"dh">>, Vec)),
    Cf = to_atom(map_get(<<"cipher">>, Vec)),
    Ha = to_atom(map_get(<<"hash">>, Vec)),
    IniPrologue  = binary:decode_hex(map_get(<<"init_prologue">>, Vec)),
    IniEphemeral = crypto:generate_key(ecdh, Dh, binary:decode_hex(map_get(<<"init_ephemeral">>, Vec))),
    RspPrologue  = binary:decode_hex(map_get(<<"resp_prologue">>, Vec)),
    RspEphemeral = crypto:generate_key(ecdh, Dh, binary:decode_hex(map_get(<<"resp_ephemeral">>, Vec))),

    Ini = vixen:new(ini, Hs, Dh, Cf, Ha, [], [{prologue, IniPrologue}]),
    vixen:set_e(Ini, IniEphemeral),

    Rsp = vixen:new(rsp, Hs, Dh, Cf, Ha, [], [{prologue, RspPrologue}]),
    vixen:set_e(Rsp, RspEphemeral),

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



to_atom(<<"25519">>) -> x25519;
to_atom(<<"448">>) -> x448;
to_atom(<<"ChaChaPoly">>) -> chacha20_poly1305;
to_atom(<<"AESGCM">>) -> aes_256_gcm;
to_atom(<<"SHA256">>) -> sha256;
to_atom(<<"SHA512">>) -> sha512;
to_atom(<<"BLAKE2s">>) -> blake2s;
to_atom(<<"BLAKE2b">>) -> blake2b.