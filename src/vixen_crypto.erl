%%%-----------------------------------------------------------------------------
%%% @doc
%%% Crypto functions and other helpers.
%%% @author ausimian
%%% @end
%%%-----------------------------------------------------------------------------

-module(vixen_crypto).
-author("ausimian").

%%%=============================================================================
%%% Export and Defs
%%%=============================================================================

%% External API
-export([
    dh/3,
    dh_len/1,
    generate_keypair/1,
    encrypt/5,
    decrypt/5,
    rekey/2,
    hash/2,
    hash_len/1,
    hkdf/4
]).

-include("vixen.hrl").

%%%=============================================================================
%%% API
%%%=============================================================================

-spec dh(Dh :: vixen:dh_fun(), Private :: vixen:key_pair(), Public :: binary) -> binary().
dh(Dh, {_, Private}, Public) when Dh =:= x25519 orelse Dh =:= x448 ->
    crypto:compute_key(ecdh, Public, Private, Dh).

-spec dh_len(vixen:dh_fun()) -> 32 | 56.
dh_len(x25519) -> 32;
dh_len(x448) -> 56.

-spec generate_keypair(Dh :: vixen:dh_fun()) -> vixen:key_pair().
generate_keypair(Dh) when Dh =:= x25519 orelse Dh =:= x448 ->
    crypto:generate_key(ecdh, Dh).

-spec encrypt(
    Cf        :: vixen:cipher_fun(),
    Key       :: iodata(),
    Nonce     :: non_neg_integer(),
    AAD       :: iodata(),
    PlainText :: iodata()
    ) -> {binary(), binary()}.
encrypt(Cf, <<Key:32/binary>>, Nonce, <<AAD/binary>>, PlainText) when
    Cf =:= chacha20_poly1305 orelse Cf =:= aes_256_gcm,
    is_integer(Nonce) andalso Nonce >= 0 andalso Nonce =< ?REKEY_NONCE
    ->
    IV = cipher_iv(Cf, Nonce),
    crypto:crypto_one_time_aead(Cf, Key, IV, PlainText, AAD, true).

-spec decrypt(
    Cf        :: vixen:cipher_fun(),
    Key       :: iodata(),
    Nonce     :: non_neg_integer(),
    AAD       :: iodata(),
    CryptText :: iodata()
    ) -> binary() | error.
decrypt(Cf, <<Key:32/binary>>, Nonce, <<AAD/binary>>, CryptText) when
    Cf =:= chacha20_poly1305 orelse Cf =:= aes_256_gcm,
    is_integer(Nonce) andalso Nonce >= 0 andalso Nonce < ?REKEY_NONCE
    ->
    IV = cipher_iv(Cf, Nonce),
    Bytes = iolist_to_binary(CryptText),
    {InText, Tag} = split_binary(Bytes, byte_size(Bytes) - 16),
    crypto:crypto_one_time_aead(Cf, Key, IV, InText, AAD, Tag, false).

-spec rekey(Cf :: vixen:cipher_fun(), Key :: <<_:256>>) -> binary().
rekey(Cf, <<Key:32/binary>>)  ->
    element(1, encrypt(Cf, Key, ?REKEY_NONCE, <<>>, <<0:256>>)).

-spec hash(Hf :: vixen:hash_fun(), Data :: iodata()) -> binary().
hash(Hf, Data) ->
    crypto:hash(Hf, Data).

-spec hash_len(vixen:hash_fun()) -> 32 | 64.
hash_len(sha256) -> 32;
hash_len(sha512) -> 64;
hash_len(blake2s) -> 32;
hash_len(blake2b) -> 64.

-spec hkdf(vixen:hash_fun(), binary(), binary(), 2 | 3) 
    -> {binary(), binary()} | {binary(), binary(), binary()}.
hkdf(Hf, Ck, Ikm, NumOutputs) when
    (((Hf =:= sha256 orelse Hf =:= blake2s) andalso (byte_size(Ck) == 32)) orelse
     ((Hf =:= sha512 orelse Hf =:= blake2b) andalso (byte_size(Ck) == 64))) 
    andalso (NumOutputs == 2 orelse NumOutputs == 3)
    ->
    Tk = hmac_hash(Hf, Ck, Ikm),
    O1 = hmac_hash(Hf, Tk, <<1>>),
    O2 = hmac_hash(Hf, Tk, [O1, <<2>>]),
    case NumOutputs of
        2 -> {O1, O2};
        3 -> {O1, O2, hmac_hash(Hf, Tk, [O2, <<3>>])}
    end.


%%%=============================================================================
%%% Internal functions
%%%=============================================================================

cipher_iv(chacha20_poly1305, Nonce) -> <<0:32, Nonce:64/little>>;
cipher_iv(aes_256_gcm, Nonce) -> <<0:32, Nonce:64/big>>.

hmac_hash(Hf, <<Key/binary>>, Data) ->
    crypto:mac(hmac, Hf, Key, Data).