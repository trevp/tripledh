
Triple Diffie-Hellman
=======================

 * **Author:** Trevor Perrin (curves @ trevp.net)
 * **Date:** 2014-10-25
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
=

This document describes key agreement protocols that can be used with
Diffie-Hellman or Elliptic Curve Diffie-Hellman key pairs.  These
protocols establish mutual authentication and forward secrecy via
three DH or ECDH operations, thus are referred to as "TripleDH"
protocols.

A few TripleDH variants are presented, and their security properties
are discussed.


2. Algorithms
=

2.1. Notation
-

    Name             Explanation
    -----            ------------
    ||               Concatenation of byte sequences
    DH(X, Y)         The Diffie-Hellman or Elliptic Curve Diffie-
                     Hellman shared secret between public keys X and Y
    KDF(Z)           A key derivation function suitable for converting
                     DH() outputs into a session key
    AE(K, D)         Authenticated encryption using symmetric key K of 
                     data D
    AEAD(K, D, AAD)  Authenticated encryption using symmetric key K of
                     data D with "additional authenticated data" AAD
    Signature(X, D)  Signature from public key X over data D
    A -> B: M        Party A sends message M to party B
    M*               Multiple instances of message M may be sent

Protocol messages are numbered.  Messages with the same number can be
sent simultaneously.  Messages with a later number shall only be sent
if the sending party has successfully sent or received at least one
instance of any earlier-numbered messages.

2.2. Variables
-

    Name             Explanation
    -----            ------------
    A                Alice's identity public key
    A'               Alice's ephemeral public key
    B                Bob's identity public key
    B'               Bob's ephemeral public key
    B"               Bob's extra ephemeral public key
    SKA              Alice's session key for sending messages
    SKB              Bob's session key for sending messages
    <any>            Any byte sequence
    ID               Identity data for the session (e.g. identity
                     public keys, certificates, names, etc.)

2.3. Setup
-

Two parties each have a long-term "identity" keypair, comprised of
Diffie-Hellman or Elliptic Curve Diffie-Hellman values.  Both
parties also have a short-term "ephemeral" keypair, also comprised of
Diffie-Hellman or Elliptic Curve Diffie-Hellman values.

All keypairs must use the same (EC)DH parameters, so that the `DH()`
function is defined between all public keys.

In some TripleDH variants we assume Bob has additional data
(signature, extra ephemeral public key).  These add security in cases
where Bob is offline and Alice is performing an asynchronous key
agreement, as explained below.

2.4. Minimal TripleDH
-

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B'

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B'))

    2. Alice -> Bob: AE(SKA, <any>)*
    2. Alice <- Bob: AE(SKB, <any>)*

2.5. Standard TripleDH
-

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B'

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B'))
    ID = A || B || <any>

    2. Alice -> Bob: AEAD(SKA, <any>, ID)*
    2. Alice <- Bob: AEAD(SKB, <any>, ID)*

2.6. Standard TripleDH with signed ephemeral
-

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B', Signature(B, B')

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B'))
    ID = A || B || <any>

    2. Alice -> Bob: AEAD(SKA, <any>, ID)*
    3. Alice <- Bob: AEAD(SKB, <any>, ID)*

2.7. Standard TripleDH with signed ephemeral and extra ephemeral
-

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B', Signature(B, B'), B"

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B') || DH(A', B"))
    ID = A || B || <any>

    2. Alice -> Bob: AEAD(SKA, <any>, ID)*
    3. Alice <- Bob: AEAD(SKB, <any>, ID)*

3. Security considerations
=

3.1. Instantiating cryptographic algorithms
-

The EC(DH) algorithm should be secure under the [Gap-DH][] assumption.
This assumption is believed to hold for common (EC)DH algorithms.

The signature algorithm should be secure when the same keypair is used
for (EC)DH and signatures.  An example is a Schnorr signature such as
[Curve25519-Signatures][] where all hash functions in the KDF and signature can be
modelled as different random oracles.

The KDF should use a collision-resistant hash to "extract" a key from
its inputs, then use a PRF to "expand" the key into session keys.  The
recommended KDF is [HKDF][] using SHA256 or SHA512 with no salt, and
the `info` variable containing a constant specific to the protocol.

3.2. Identity binding
--

In Minimal TripleDH an attacker might be able to tweak some of the
transmitted (EC)DH values such that Alice and Bob still agree on
secret session keys.  For example:

 * In (EC)DH systems with a cofactor and where public keys are not
   validated for main subgroup membership it may be possible to encode
   a public key as different byte sequences (e.g. [Curve25519][]).  An
   attacker could change the encoding of identity public keys so that
   Alice sees an encoding of Bob's public key that Bob might not
   recognize.

 * An attacker could exponentiate Bob's (EC)DH keys by a constant when
   sending them to Alice, and do the same to Alice's keys when sending
   them to Bob.  Alice and Bob will still calculate a shared session
   key, but won't see each other's correct identity public keys.  This
   doesn't accomplish much, since an attacker could always present
   Alice and Bob with the attacker's own public keys and become a
   "man-in-the-middle".

Some protocols avoid these issues by hashing identity data into the
session key (e.g. [KEA+][]).  Standard TripleDH instead includes the
identity data as "additional authenticated data" in encrypted
messages.

Identity data includes the identity public keys, and may also include
certificates, names and addresses, protocol versions and offered
features, and other information which both parties want to ensure they
are seeing the same values for.

3.3. Strong forward secrecy
--

Minimal and Standard TripleDH only provide "weak forward secrecy" (in
the terminology of [HMQV][]).  This means forward secrecy is achieved
for sessions without an active attacker, but an active attacker could
cause encrypted messages to be sent without forward secrecy:

 1) The attacker sends Bob's identity public key to Alice along with an
   ephemeral public key generated by the attacker.

 2) Alice calculates the session key and encrypts a message for Bob.
   To decrypt the message, the attacker only needs to compromise Bob's
   identity private key.

Strong forward secrecy could be achieved by adding a key confirmation
step.  For example, Standard TripleDH could be modified to:

    2. Alice -> Bob: AEAD(SKA, "", ID || "key confirmation")
    2. Alice <- Bob: AEAD(SKB, "", ID || "key confirmation")

    3. Alice -> Bob: AEAD(SKA, <any>, ID)*
    3. Alice <- Bob: AEAD(SKB, <any>, ID)*

The "signed ephemeral" variants of TripleDH achieve strong forward
secrecy without extra messages, provided Alice sends the first
encrypted message.  The signature prevents Bob's ephemeral from being
forged.  Bob's verification of Alice's encrypted message prevents
Alice's ephemeral from being forged. This allows strong forward
secrecy in an asynchronous setting where Bob is offline but has
published a signed ephemeral.

3.4. Ephemeral reuse
--

At least one party must generate a unique ephemeral key for each
protocol run.  Reuse of ephemeral keys by both parties is not allowed,
and results in catastrophic security failure (reuse of session keys).

Reuse of ephemeral keys by a single party is allowed, but reduces
security:

 * Encrypted messages can be replayed unless the party reusing its
   ephemeral takes other steps (such as maintaining a blacklist of
   already-received messages).

 * Forward secrecy is reduced since compromising a reused ephemeral
   private key reveals past session keys.

 * Impersonation resistance is reduced since compromising a reused
   ephemeral private key allows impersonating other parties to the
   compromised party.

In an asynchronous setting many parties might send messages to Bob by
reusing a signed ephemeral he published.

To improve security in this case Bob might send a list of one-time-use
"extra ephemeral" keys to some intermediary which hands them out to
anyone who wants to send Bob a message.  Until these keys run out,
messsages to Bob can use the "signed ephemeral and extra ephemeral"
variant of TripleDH.  Messages sent using such extra ephemerals cannot
be replayed and have improved forward secrecy, assuming Bob deletes
the extra ephemeral private key on receiving the message.

3.5. Deniability
-

TripleDH doesn't give either party data that could be presented to
arbitrary third parties as cryptographic evidence of a relationship,
provided the following conditions are met:

 * Any signed ephemerals are published so they could be retrieved by
   anyone, thus possessing a signed ephemeral provides no evidence of
   a relationship.

 * No party sends an encrypted message until it has either deleted its
   own ephemeral private key or successfully verified an encrypted
   message from the other party.  (If this rule is not followed an
   attacker can construct an ephemeral public key with an obviously
   unknown private key, then present the victim's encrypted message
   to third parties who can confirm the relationship if they
   compromise the victim's identity and ephemeral private keys.)

4. Acknowledgements
=

The TripleDH structure was proposed in [Kudla-Paterson][] and
[NAXOS][], extending earlier "Double DH" protocols like "Protocol 4"
from [Blake-Wilson][] et al.

The standard, signed ephemeral, and extra ephemeral variants were
developed by Trevor Perrin and Moxie Marlinspike.

Thanks to Mike Hamburg for discussion of identity binding and
Curve25519 public keys.

Thanks to Matthew Green for discussion of deniability attacks and
conditions.


5. References
=

[Gap-DH]: #Gap-DH
<a name="Gap-DH">**Gap-DH:**</a>
<http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.115.2077>

[Curve25519-Signatures]: #Curve25519-Signatures
<a name="Curve25519-Signatures">**Curve25519-Signatures:**</a>
https://github.com/trevp/curve25519sigs/blob/master/curve25519sigs.md

[HKDF]: #HKDF
<a name="HKDF">**HKDF:**</a>
<http://tools.ietf.org/html/rfc5869>

[Curve25519]: #Curve25519
<a name="Curve25519">**Curve25519:**</a>
<http://cr.yp.to/ecdh/curve25519-20060209.pdf>

[KEA+]: #KEA+
<a name="KEA+">**KEA+:**</a>
<http://research.microsoft.com/en-us/um/people/klauter/security_of_kea_ake_protocol.pdf>

[HMQV]: #HMQV
<a name="HMQV">**HMQV:**</a>
<http://eprint.iacr.org/2005/176.pdf>

[Kudla-Paterson]: #Kudla-Paterson
<a name="Kudla-Paterson">**Kudla-Paterson:**</a>
<http://www.isg.rhul.ac.uk/~kp/ModularProofs.pdf>

[NAXOS]: #NAXOS
<a name="NAXOS">**NAXOS:**</a>
<http://research.microsoft.com/pubs/81673/strongake-submitted.pdf>

[Blake-Wilson]: #BlakeWilson
<a name="Blake-Wilson">**Blake-Wilson:**</a>
<http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.27.8493>
