-define(REKEY_NONCE, 18446744073709551615).
-define(SEP, {}).

-ifdef(TEST).
-define(INSPECT(L, V), (begin io:format(user, "~p: ~p~n", [L, V]), V end)).
-else.
-define(INSPECT(L, V), V).
-endif.
