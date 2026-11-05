# Use Case Model

This document walks through the DLC (Discreet Log Contract) "betting" use case that this library supports. It explains who is involved, what each party does and in what order, and where the cryptography comes in.

---

## 1. Basic Use Case

### 1.1 Actors

| Actor | Role |
|-------|------|
| **Alice** (`A`) | Betting party |
| **Bob** (`B`) | Betting party (Alice's counterparty) |
| **Oracle** (`O`) | Independent service that attests to real-world events. It does **not** know about the betting parties or their contracts. |

### 1.2 Scenario

Alice and Bob want to make a bet with each other. Each puts in some bitcoin, and the pot is split between them according to the outcome of a future event.

> **Example:** Alice wants weather insurance. The event is *"Does it rain at location L on day D?"* If it rains, Alice gets paid; if not, Bob keeps the stake.

### 1.3 Keys and Event Announcement

Each participant holds a key pair (secret key, public key):

| Owner | Secret key | Public key |
|-------|-----------|------------|
| Alice | $S_A$ | $P_A$ |
| Bob | $S_B$ | $P_B$ |
| Oracle | $S_O$ | $P_O$ |

For every future event `E` it agrees to serve, the Oracle publishes an **event announcement** containing:

- **$t_E$**: the time at which the outcome will be known and attested.
- **The outcome set**: a well-defined list of possible outcomes, each with its own message (hash) that the Oracle will sign.
- **$N_{PE}$**: a public nonce, unique to this event. The matching secret nonce **$N_{SE}$** stays private to the Oracle.

The Oracle commits to publishing **exactly one** attestation signature for the event, at time $t_E$. The signature covers the message of the actual outcome and is made with the announced nonce.

> **Why the nonce matters:** since the nonce $N_{PE}$ is fixed ahead of time, anyone can compute the *signature point* (adaptor point) for every possible outcome from $P_O$, $N_{PE}$ and the outcome's message, before the outcome is known. That point is what the parties' signatures get encrypted to. If the Oracle signed two different outcomes with the same nonce, its secret key would leak, which gives it a strong reason to attest only once.

To keep things simple, the rest of this section uses a **binary event** with two outcomes, $O1_E$ and $O2_E$.

### 1.4 Protocol Steps

#### Setup

1. **Agree on terms.**
   Alice and Bob look at the available Oracles and their announced events, and agree on:
   - the Oracle and the event,
   - how much each contributes (e.g. equal amounts),
   - the payout for each outcome (e.g. $O1_E$: Alice takes everything; $O2_E$: Bob takes everything).

2. **Build the funding transaction.**
   Alice and Bob jointly build a **funding transaction**. Each adds inputs for their own contribution. Its output is a **2-of-2 multisig** UTXO that can only be spent with signatures from both $S_A$ and $S_B$.
   *They do not sign it yet.*

3. **Build the CETs.**
   For each outcome they build a **Contract Execution Transaction (CET)**. Every CET spends the funding output and pays the parties according to that outcome's payout.
   The CETs conflict with each other because they all spend the same UTXO, so at most one of them can ever confirm.

4. **Exchange adaptor signatures.**
   For each CET, each party:
   - computes the adaptor point for that CET's outcome (from $P_O$, $N_{PE}$ and the outcome message),
   - creates an **adaptor signature**: its (ECDSA) signature on the CET, *encrypted* to that adaptor point (see [Appendix A.4](#a4-ecdsa-adaptor-signatures)),
   - sends the adaptor signature to the other party.

   Each party checks the adaptor signatures it receives. An adaptor signature on its own is not a valid signature. It can only be turned into one using the Oracle's attestation for **that specific outcome**.

5. **Sign and broadcast the funding transaction.**
   Only after all CET adaptor signatures have been exchanged and checked do the parties sign their funding inputs. The funding transaction is then broadcast and waits for confirmation.

   > Doing it in this order means neither party ever has funds locked in the multisig without a signed way out.

#### Waiting

6. **Wait for the event.**
   Nothing happens on-chain until $t_E$.

#### Settlement

7. **Oracle attests.**
   After $t_E$ the Oracle determines the actual outcome (say $O1_E$) and publishes its attestation: a BIP340 Schnorr signature over the outcome's message, made with the event nonce $N_{SE}$ (see [Appendix A.3](#a3-oracle-attestation-schnorr-with-a-pre-committed-nonce)).

8. **Decrypt and complete the CET.**
   Either party sees the attestation. The scalar part of that signature is the decryption key for the adaptor point of outcome $O1_E$. Using it, a party:
   - decrypts the **other party's** adaptor signature on the $O1_E$ CET into a valid signature,
   - adds **their own** signature on the same CET,
   - now has both signatures needed for the 2-of-2, and broadcasts the CET.

   Either party can do this. In practice the party that benefits from the outcome has the most reason to act.

The bet is now settled. ✅

### 1.5 Sequence Overview

```
Oracle             Alice                       Bob
  |                  |                          |
  |-- announce E ---->|------------------------->|  (t_E, outcomes, N_PE)
  |                  |<---- agree on terms ---->|
  |                  |<-- build funding tx ---->|  (unsigned)
  |                  |<---- build CETs -------->|
  |                  |<- adaptor sigs (CETs) -->|  exchange & verify
  |                  |<- sign funding tx ------>|  broadcast, confirm
  |                  |                          |
  |   ... wait until t_E ...                    |
  |                  |                          |
  |-- attestation -->|------------------------->|  sig over true outcome
  |                  |  decrypt counterparty's adaptor sig,
  |                  |  add own sig, broadcast winning CET
```

---

## 2. Fallback: Refund Transaction

If the Oracle never publishes an attestation (it goes offline, shuts down, etc.), the funds would stay locked in the funding output forever. A **refund transaction** guards against this.

- **What it does:** spends the funding output and pays each party back their original contribution. Fees are deducted from the amounts, e.g. split in proportion to each party's contribution.
- **Timelock:** it is only valid after $t_E$ **plus a buffer period** (e.g. two weeks). This gives the Oracle and the CETs time to take effect first.
- **When it is signed:** both parties sign the refund transaction during setup, **before** the CET adaptor signatures and, in any case, before the funding transaction is signed.

**Result:** no matter what happens to the Oracle or the CETs, both parties can always get their funds back once the timelock expires.

---

## 3. Multiple Outcomes

The basic use case has two outcomes. Here the event has **`N` outcomes**, where `N` can be large. The outcomes have no structure: they are just a list, e.g. *"Which team wins the tournament?"*. The actors, the funding transaction, the refund transaction and the order of steps stay the same. Only the following changes:

- **Event announcement:** the outcome set lists `N` outcomes, each with its own message. There is still a **single** nonce $N_{PE}$, because the Oracle signs exactly one message.
- **Agreeing on terms (step 1):** the payout is given for each of the `N` outcomes.
- **Building the CETs (step 3):** one CET per outcome, so `N` CETs. All of them spend the same funding output, so at most one can confirm.
- **Adaptor signatures (step 4):** each party creates `N` adaptor signatures, one per CET, each encrypted to that outcome's adaptor point. Outcomes with the same payout still need separate CETs, because each outcome has its own adaptor point.
- **Attestation and settlement (steps 7–8):** unchanged. The Oracle signs the message of the actual outcome, and the parties complete the CET for that outcome.

**Practical limit on `N`.** Signature operations are expensive. For **every** CET, each party creates an adaptor signature (EC multiplications plus a DLEQ proof), and the counterparty has to verify it. All of this has to be done, sent and stored before funding. So in practice the number of distinct outcomes is **limited, to tens of thousands at most**.

---

## 4. Numerical Outcomes

A special case is a **numerical** outcome, e.g. the BTC/USD exchange price at $t_E$. Depending on the range and precision, the number of distinct values can be very large: a price with 7 decimal digits already has 10 million possible values. Treated as in section 3, each value would need its own CET, far over the practical limit.

Grouping values with the same payout doesn't help on its own: with a single nonce, each value has its own adaptor point, so a CET covering a range would still need one adaptor signature per value in it.

The **digit decomposition** scheme, which is what the library implements, reduces the complexity. The Oracle attests each digit separately, so one CET (one adaptor signature) can cover a whole range of values.

> **Example:** Alice and Bob bet on the BTC/USD price at day D. Alice's share of the pot grows with the price: below 90,000 Bob takes everything, above 110,000 Alice does, and in between it is split proportionally.

Compared with section 3, the following changes:

**Event announcement.**
- The value is written with a fixed number of decimal digits `D` (e.g. 7 or 9). The Oracle publishes `D` nonces, **one per digit position**, instead of a single $N_{PE}$.
- It also publishes the message template for each digit, e.g. `Outcome:btcusd1741474920:{digit_index}:{digit_outcome}`. The digit's position and its value are both part of the message.

**Agreeing on terms (step 1).**
- The payout is a function of the outcome (a payout curve) rather than a table with one row per outcome.
- The parties split the value range into **intervals**, each with a constant payout. The intervals must cover every value the Oracle could attest, with no gaps and no overlaps. Values outside the range of interest go into catch-all intervals at either end.

**Building the CETs (step 3).**
- One CET per interval or part of an interval, not one per possible value.
- Each CET is described by a **digit pattern** of length `D`. A position is either a fixed digit or a wildcard (`*`). To describe a range, the wildcards are the trailing positions. The library itself accepts a wildcard in any position. For example, `0096***` covers 96,000–96,999.
- An interval that doesn't line up with these boundaries is split into a few patterns. For example, 96,500–97,999 becomes `00965**`, `00966**`, …, `00969**`, `0097***`. CETs whose patterns fall in the same interval have the same payout.
- The practical limit from section 3 still applies, but now to the number of **patterns**, not of values. Typically the range is divided into a few thousand intervals. The payout curve is approximated accordingly: wide intervals where the payout is flat, finer ones where it changes.

**Adaptor points (step 4).**
- The adaptor point of a CET is the **sum** of the per-digit signature points at its fixed positions. Wildcard positions contribute nothing. Only `D × 10` per-digit points have to be computed, whatever the number of CETs.
- Each per-digit point depends on that position's nonce and on a message containing the position. So the same digits in a different order (e.g. `961**` vs `916**`) give unrelated adaptor points.

**Attestation (step 7).**
- The Oracle publishes `D` Schnorr signatures, one per digit of the actual value, each made with that position's nonce.
- It must still attest each digit only once. Signing two different values for the same position with the same nonce leaks its key, just as in the binary case.

**Settlement (step 8).**
- The party looks for the one CET whose pattern matches the attested value.
- It adds up the scalars of the attestations at that pattern's fixed positions to get the decryption key. The attestations for wildcard positions are ignored.
- Decrypting the counterparty's adaptor signature and broadcasting the CET work as before.

See [Appendix A.5](#a5-numeric-outcomes-digit-decomposition) for the cryptographic details.

---

## Appendix A: Cryptography Details

This appendix gives the cryptography behind the protocol, as implemented in [src/adaptor_signature.rs](src/adaptor_signature.rs). Primitives come from [`secp256k1-zkp`](https://docs.rs/secp256k1-zkp/latest/secp256k1_zkp/).

### A.1 Notation

All operations are on the **secp256k1** curve.

| Symbol | Meaning | Name in main text |
|--------|---------|-------------------|
| $G$ | Curve generator point | |
| $n$ | Group order | |
| $x_A, x_B$ | Alice's / Bob's secret keys | $S_A$, $S_B$ |
| $X_A = x_A G,\ X_B = x_B G$ | Alice's / Bob's public keys | $P_A$, $P_B$ |
| $x_O$, $X_O = x_O G$ | Oracle secret / public key | $S_O$, $P_O$ |
| $k$, $R = kG$ | Oracle event nonce (secret / public) | $N_{SE}$, $N_{PE}$ |
| $m$ | Message signed by the Oracle (one per outcome) | |
| $z$ | Sighash of a CET (the message signed by the parties) | |
| $H_{\text{BIP340}}(\cdot)$ | BIP340 tagged hash, tag `BIP0340/challenge` | |

Points used in Schnorr computations are **x-only** (32 bytes), as in BIP340. When one has to be turned back into a full point, the even-$y$ version is used (prefix `0x02`).

### A.2 Signature Schemes Used

There are **two** signature schemes in the protocol, used for different things:

| Who signs | What | Scheme |
|-----------|------|--------|
| Oracle | Outcome attestation | **Schnorr (BIP340)**, with a nonce fixed in advance |
| Alice, Bob | Funding, CET and refund transactions | **ECDSA** (SIGHASH_ALL), spending a 2-of-2 multisig |
| Alice, Bob | CET pre-signatures | **ECDSA adaptor signatures**, encrypted to an adaptor point taken from the Oracle's Schnorr attestation |

Combining them works because the scalar part of a Schnorr signature is a discrete log that anyone can predict **as a point** in advance. That point serves as the encryption key for an ECDSA adaptor signature.

### A.3 Oracle Attestation (Schnorr with a Pre-committed Nonce)

**Message.** An outcome is described by a string, and the message is its SHA-256 hash:

```math
m = \mathrm{SHA256}(\text{outcome string})
```

> Note: this is plain SHA-256 of the string. The [dlcspecs](https://github.com/discreetlogcontracts/dlcspecs) instead use a tagged hash (`DLC/oracle/attestation/v0`), so the two are not wire-compatible.

**Nonce.** The Oracle generates $k$ ahead of time and publishes $R = kG$ in the event announcement (see [A.6](#a6-nonce-generation)).

**Signing.** BIP340 signing, except that the nonce is the pre-committed $k$ instead of one derived from the message (`schnorrsig_sign_with_nonce`, which plugs a constant-nonce function into `secp256k1_schnorrsig_sign_custom`):

```math
e = H_{\text{BIP340}}(R \parallel X_O \parallel m), \qquad s = k + e \cdot x_O \bmod n
```

The attestation is the 64-byte signature $(R, s)$. (As BIP340 requires, $k$ and $x_O$ are implicitly negated where needed so that $R$ and $X_O$ have even $y$.)

**Signature point.** Since $R$, $X_O$ and $m$ are all known **before** the event, anyone can compute the point that $s$ will be the discrete log of (`schnorrsig_compute_sig_point`):

```math
S_m = s \cdot G = R + e \cdot X_O
```

Each possible outcome $m_i$ gets its own $S_{m_i}$. When the Oracle attests outcome $m_i$, it reveals $s_i$, the secret key for exactly that point and for no other.

**Signing only once.** If the Oracle signed two different messages $m_1 \ne m_2$ with the same $R$:

```math
s_1 - s_2 = (e_1 - e_2)\, x_O \;\Rightarrow\; x_O = \frac{s_1 - s_2}{e_1 - e_2}
```

so attesting two conflicting outcomes gives away the Oracle's secret key.

### A.4 ECDSA Adaptor Signatures

The parties pre-sign each CET with an **ECDSA adaptor signature** (`EcdsaAdaptorSignature` in secp256k1-zkp, which follows Lloyd Fournier's one-time VES construction). Below, $Y$ is the adaptor (encryption) point and $y$ its discrete log, so $Y = yG$.

**Encrypt (pre-sign)**: done by the signer with secret key $x$, on sighash $z$ (`EcdsaAdaptorSignature::encrypt`):

1. Pick a random nonce $k'$.
2. Compute $R' = k' G$ and $\hat{R} = k' Y$.
3. Let $r = \hat{R}.x \bmod n$ (the x-coordinate of $\hat{R}$).
4. Compute $\hat{s} = k'^{-1}(z + r x) \bmod n$.
5. Produce a DLEQ proof $\pi$ that $\log_G R' = \log_Y \hat{R}$.

The adaptor signature is $(\hat{R}, R', \hat{s}, \pi)$.

**Verify**: done by the counterparty, who knows $X = xG$, $z$ and $Y$ (`EcdsaAdaptorSignature::verify`):

- Check the DLEQ proof $\pi$.
- Check that $\hat{s} R' = zG + rX$.

This shows that the adaptor signature turns into a valid ECDSA signature by $X$ on $z$ **once $y$ is known**, and not otherwise.

**Decrypt**: done by whoever learns $y$ (`EcdsaAdaptorSignature::decrypt`):

```math
s = \hat{s} \cdot y^{-1} \bmod n
```

$(r, s)$ is now a valid ECDSA signature, because the effective nonce is $k' y$ and $(k' y)\, G = \hat{R}$:

```math
s = (k' y)^{-1}(z + r x)
```

> **Side effect (recovery):** anyone holding both $\hat{s}$ and the decrypted $s$ can recover $y = \pm\hat{s} / s$ (the sign is ambiguous because of low-$s$ normalization). It doesn't matter in the DLC flow, because by then $y$ has been made public by the Oracle anyway.

### A.5 Numeric Outcomes: Digit Decomposition

The library supports **numeric** outcomes written in base 10 with a fixed number of digits $D$ (`num_digits`).

**Per-digit attestation.** The Oracle commits to one nonce $R_d$ **per digit** $d \in \{0, \dots, D-1\}$ and attests each digit on its own. The message for "digit $d$ has value $v$" comes from a string template, for example:

```
Outcome:btcusd1741474920:{digit_index}:{digit_outcome}
```

```math
m_{d,v} = \mathrm{SHA256}(\text{template}[d, v]), \qquad
S_{d,v} = R_d + H_{\text{BIP340}}(R_d \parallel X_O \parallel m_{d,v}) \cdot X_O
```

That gives $D \times 10$ signature points, all computed in advance.

**CET patterns (wildcards).** Each CET is described by a pattern of length $D$. A position is either a fixed digit `0`–`9` or a wildcard (any other character, e.g. `*`). A CET's adaptor point is the **sum** of the signature points at its fixed positions:

```math
Y_{\text{CET}} = \sum_{d \,:\, \text{pattern}[d] \in 0..9} S_{d,\ \text{pattern}[d]}
```

For example, with $D = 4$, the pattern `95**` covers outcomes 9500–9599 and has $Y = S_{0,9} + S_{1,5}$. A small set of prefix patterns can cover any range of values (the "digit decomposition" of the dlcspecs).

**Signing.** For each CET $j$, each party produces an ECDSA adaptor signature on the CET sighash $z_j$, encrypted to $Y_{\text{CET}_j}$ (`create_cet_adaptor_signatures`). The counterparty checks all of them (`verify_cet_adaptor_signatures`).

**Settlement.** The Oracle publishes $D$ signatures $(R_d, s_d)$, one per digit of the actual value. For the CET whose pattern matches that value, the party:

1. takes the scalar $s_d$ from each attestation at the pattern's fixed positions (`schnorrsig_decompose`),
2. adds them up to get the adaptor secret:

   ```math
   y = \sum_{d \,\in\, \text{fixed}} s_d \bmod n, \qquad yG = Y_{\text{CET}}
   ```

3. decrypts the counterparty's adaptor signature with $y$ and checks that the result is a valid ECDSA signature,
4. signs the CET with their own key, and checks that signature too (`create_final_cet_signatures`).

Both signatures are DER-encoded with the `SIGHASH_ALL` byte appended, ready to go into the witness of the 2-of-2 multisig input.

The binary event in the main text is the special case of a single digit with only two values in use.

### A.6 Nonce Generation

The Oracle's per-event nonces must be **unpredictable** and **never reused**. Anyone who learns $k$ can compute $x_O = (s - k)/e$ from one attestation.

`create_nonce(event_id, index)` derives:

```math
k = \mathrm{SHA256}(\text{nonce\_seed} \parallel \text{event\_id} \parallel \text{index}_{\text{BE32}} \parallel \text{aux\_rand}_{32})
```

- `nonce_seed`: derived from the master secret and used only for this. Without it, nobody else can compute the nonce.
- `event_id`, `index`: domain separation, so different events and digits never collide.
- `aux_rand`: 32 bytes of fresh OS randomness. Even the master-secret holder can't reproduce the nonce, which guards against a buggy or duplicated derivation.

Since the result is not reproducible, the Oracle has to **store** the secret nonce until it attests.

> ⚠️ `create_deterministic_nonce` hashes a fixed public string containing only `event_id` and `index`, so **anyone** can compute that nonce. It must not be used for real attestations.

### A.7 Key Derivation

Party and Oracle keys are HD-wallet child keys, derived from a seed along the BIP84 account path:

- mainnet: `m/84'/0'/0'/<index4>/<index5>`
- signet: `m/84'/1'/0'/<index4>/<index5>`

### A.8 References

- [BIP340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [DLC specifications (dlcspecs)](https://github.com/discreetlogcontracts/dlcspecs), in particular *Oracle*, *Adaptor Signatures* and *Numeric Outcome* (digit decomposition)
- [secp256k1-zkp ECDSA adaptor signature module](https://github.com/BlockstreamResearch/secp256k1-zkp/blob/master/src/modules/ecdsa_adaptor/), with the spec in `ecdsa_adaptor.md`
- T. Dryja, [*Discreet Log Contracts*](https://adiabat.github.io/dlc.pdf) (original paper)
