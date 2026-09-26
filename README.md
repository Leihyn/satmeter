# Satmeter

**Metered API access with no account, no API key, and nothing stored about you.**

Charging for an API normally means signup, an API key, a balance in a table, and a billing
relationship. Every one of those is a row about you that somebody has to keep, secure, and
eventually hand over. L402 replaces the lot with a credential that carries its own limits.

Live: https://satmeter.vercel.app

## The mechanism

A macaroon is a bearer credential whose signature is an HMAC chain:

```
sig₀     = HMAC(root_key, identifier)
sig_{i+1} = HMAC(sig_i, caveat_i)
```

Two properties fall out of that shape, and the whole design rests on them.

**Anyone holding the credential can narrow it.** Appending a caveat and re-signing needs only the
current signature, not the root key. So you can hand a subcontractor a copy capped at three calls
without asking the server and without the server storing anything new.

**Nobody can widen it back.** There are two ways to try, and they fail for two different reasons:

- *Append a looser caveat.* The signature stays valid, because appending is always allowed. But
  every caveat must hold, so the tighter one still binds. This fails on **policy**.
- *Delete the tighter caveat.* Policy would then allow it, but the signature was built by chaining
  that caveat in, and recovering the earlier signature means inverting HMAC. This fails on
  **cryptography**.

The payment leg is the standard L402 one. The credential's identifier contains the invoice's
payment hash. Paying a Lightning invoice reveals its preimage and only paying does, so presenting
`Authorization: L402 <macaroon>:<preimage>` proves payment with no record of who you are.

## Running it

Static. No build, no server, no node, no wallet.

```
python3 -m http.server 8000
```

Then open `http://localhost:8000`. Append `?demo` to run the whole flow automatically.

## What is implemented

Macaroon minting, attenuation and verification over an HMAC-SHA256 chain; caveat evaluation;
BOLT-11 invoice construction on testnet with a real recoverable ECDSA signature, plus decoding
and payee-key recovery; and preimage-to-payment-hash proof.

The invoice is a genuine testnet BOLT-11 — it decodes in any Lightning tool, and the page proves
its signature by recovering the payee's public key from it.

Not implemented: routing a payment over Lightning, third-party caveats and their discharge
macaroons, and invoice expiry. No node is contacted and no payment is made, so this page cannot
move a satoshi on any network. The payment step is simulated, and the page says so where it
happens rather than in a footnote.

## A note on statelessness

The server stores its root key and one counter keyed by payment hash. That is the honest claim:
caveats are enforced with no state at all, but *counting calls* needs somewhere to count. What it
does not store is an account, an identity, an email, or a card — it cannot tell two customers
apart except by a hash it learns only when they spend.

## Verification

The page's own script is loaded into Node behind a DOM shim, so the tests drive the shipped code
rather than a reimplementation. 27 assertions:

```
PASS  server answers 402 Payment Required
PASS  the invoice is testnet                        network testnet (lntb)
PASS  the invoice signature was validated by key recovery
PASS  authorized request returns 200
PASS  delegated copy verifies against the same root
PASS  appending a wider cap still verifies (signature is fine)
PASS  but the server still permits only 3
PASS  removing the cap breaks the chain
PASS  the server rejects the stripped credential with 401
PASS  the meter refuses past its cap
PASS  and it stops at zero, never negative
```

## Dependencies

`@noble/secp256k1` v2, vendored, for the invoice signature and key recovery. WebCrypto for
SHA-256 and HMAC-SHA256. bech32 and BOLT-11 written for this project. No framework, no build step.

## Licence

MIT.
