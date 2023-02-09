vixen
=====

An implementation of the [Noise Protocol Framework](https://noiseprotocol.org/) for the BEAM.

Work-In-Progress! Do not use.

Build
-----

    $ rebar3 compile

Use
---

```Elixir
defmodule Initiator do
  def connect(responder) do
    hs = :vixen.new(:ini, :NN, :x25519, :chacha20_poly1305, :sha256, [])
    {:continue, req} = :vixen.write(hs)
    send(responder, {self(), req})

    rsp =
      receive do
        {^responder, rsp} -> rsp 
      end
    {:ok, ""} = :vixen.read(hs, rsp)
    
    # Handshake complete, channel established
    send(responder, :vixen.write("Hello world"))
  end
end

defmodule Responder do
  def respond(initiator) do
    hs = :vixen.new(:rsp, :NN, :x25519, :chacha20_poly1305, :sha256, [])

    rsp =
      receive do
        {^initiator, rsp} -> rsp 
      end
    {:continue, ""} = :vixen.read(hs, rsp)

    {:ok, req} = :vixen.write(hs)
    # Handshake complete, channel established

    send(initiator, {self(), req})

    "Hello world" =
      receive do
        ciphertext ->
            {:ok, plaintext} = :vixen.read(hs, ciphertext)
            plaintext
      end
  end
end
```