
Triple Diffie-Hellman
=======================

 * **Author:** Trevor Perrin (curves @ trevp.net)
 * **Date:** 2014-10-28
 * **Revision:** 00 (work in progress)
 * **Copyright:** This document is placed in the public domain

1. Introduction
=

This document describes key agreement protocols that can be used with
Diffie-Hellman over finite field or elliptic curve groups.  These
protocols establish mutual authentication and forward secrecy via
three DH operations, thus are referred to as "TripleDH" protocols.

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
    KDF(Z)           A key derivation function for converting DH()
                     outputs into a session key
    AE(K, D)         Authenticated encryption of data D using symmetric
                     key K
    AEAD(K, D, AAD)  Authenticated encryption of data D with additional
                     authenticated data AAD using symmetric key K
    Signature(X, D)  Signature from public key X over data D
    A -> B: M        Party A sends message M to party B
    M*               Multiple instances of message M may be sent

We use "DH" to mean the Diffie-Hellman algorithm over finite field or
elliptic curve groups.  We use multiplicative group terminology, but
everything here applies to elliptic curve groups as well.

Protocol messages are shown with numbers.  Messages with the same
number can be sent simultaneously or in any order.  Messages with a
later number shall only be sent if the sending party has successfully
sent or received at least one instance of any earlier-numbered
messages.

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
    <data>           Any byte sequence
    ID               Identity data for the session (e.g. identity
                     public keys, certificates, names, etc.)

2.3. Setup
-

Two parties each have a long-term "identity" DH key pair.  Both
parties also have a short-term "ephemeral" key pair.  All key pairs
must use the same DH group, so that the `DH()` function is defined
between all public keys.

In some TripleDH variants the Alice and Bob roles are symmetric, and
the parties assign themselves roles based on any signal available
(e.g. the initiator of the protocol may be Alice; or they may assign
roles by comparing public keys).  In the "signed ephemeral" variants
Bob is assumed to be offline, with Alice sending the first encrypted
message.

After exchanging public keys the parties calculate shared session
keys.  The session keys can be used to exchange encrypted and
authenticated messages with forward secrecy, as shown below.

2.4. Minimal TripleDH
-

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B'

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B'))

    2. Alice -> Bob: AE(SKA, <data>)*
    2. Alice <- Bob: AE(SKB, <data>)*

2.5. Standard TripleDH
-

The minimal variant is susceptible to identity binding issues in some
cases (see Section 3.2).  The recommended solution is to include
identity data as "additional authenticated data" in the encrypted
messages.

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B'

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B'))
    ID = A || B || <data>

    2. Alice -> Bob: AEAD(SKA, <data>, ID)*
    2. Alice <- Bob: AEAD(SKB, <data>, ID)*

2.6. Standard TripleDH with signed ephemeral
-

The standard variant is susceptible to weak forward secrecy issues in
some cases (see Section 3.3).  If Alice is sending the first encrypted
message, this can be addressed by having Bob publish a signature over
his ephemeral public key.

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B', Signature(B, B')

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B'))
    ID = A || B || <any>

    2. Alice -> Bob: AEAD(SKA, <data>, ID)*
    3. Alice <- Bob: AEAD(SKB, <data>, ID)*

2.7. Standard TripleDH with signed ephemeral and extra ephemeral
-

The signed ephemeral variant is susceptible to key reuse issues if the
signed ephemeral is reused over a long timeframe (see Section 3.4).
One way to mitigate this is to add a shorter-lived "extra ephemeral"
public key.

    1.  Alice -> Bob: A, A'
    1.  Alice <- Bob: B, B', Signature(B, B'), B"

    SKA || SKB = KDF(DH(A, B') || DH(A', B) || DH(A', B') || DH(A', B"))
    ID = A || B || <any>

    2. Alice -> Bob: AEAD(SKA, <data>, ID)*
    3. Alice <- Bob: AEAD(SKB, <data>, ID)*

3. Security considerations
=

3.1. Choosing cryptographic algorithms
-

The DH group should be one where the [Gap-DH][] assumption holds.
This assumption is believed to hold for common DH groups.

The signature algorithm should be secure when the same key pair is
used for DH and signatures.  An example is a Schnorr signature such as
[Curve25519-Signatures][] where all hash functions in the KDF and
signature can be modelled as different random oracles.

The KDF should use a collision-resistant cryptographic hash function
to "extract" a key from its inputs, then use a PRF to "expand" the key
into session keys.  The recommended KDF is [HKDF][] using SHA256 or
SHA512 with a constant or absent salt, and the `info` variable containing
a constant specific to the protocol.

3.2. Identity binding
--

In Minimal TripleDH an attacker might be able to tweak some of the
transmitted DH values such that Alice and Bob still agree on secret
session keys.  For example:

 * In DH systems with a cofactor, and where public keys are not
   validated for main subgroup membership, it may be possible to
   encode a public key as different byte sequences
   (e.g. [Curve25519][]).  An attacker could change the encoding of
   Bob's identity public key so that Alice sees an encoding that Bob
   might not recognize.

 * An attacker could exponentiate Bob's DH keys by a constant when
   sending them to Alice, and do the same to Alice's keys when sending
   them to Bob.  Alice and Bob will still calculate a shared session
   key, but won't see each other's correct identity public keys.  This
   doesn't accomplish much, since an attacker could always present
   Alice and Bob with the attacker's own public keys and become a
   "man-in-the-middle".

Some protocols avoid these issues by hashing identity data into the
session key (e.g. [KEA+][]).  Standard TripleDH instead includes the
identity data as "additional authenticated data" in encrypted
messages, due to IPR concerns.

Identity data includes the identity public keys, and may also include
certificates, names, protocol versions and offered features, and other
information which both parties want to ensure they are seeing the same
values for.

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

Reuse of ephemeral keys is allowed if the reusing party sends
encrypted messages using randomized encryption (e.g. a random IV).
Otherwise, the reusing party might encrypt different messages with the
same session key and IV, resulting in a catastrophic security failure.

Reusing ephemeral keys reduces security:

 * Encrypted messages can be replayed unless the party reusing its
   ephemeral takes other steps (such as maintaining a blacklist of
   already-received messages).

 * Forward secrecy is reduced since compromising a reused ephemeral
   private key reveals past session keys.

 * Impersonation resistance is reduced since compromising a reused
   ephemeral private key allows impersonating other parties to the
   compromised party.

In an asynchronous setting many parties might send messages to Bob
before he's able to publish new signed ephemeral(s).

To improve security in this case Bob might send a list of one-time-use
ephemeral keys to some intermediary which hands them out to anyone who
wants to send Bob a message.  Until these keys run out, messsages to
Bob cannot be replayed and have good forward secrecy, assuming Bob
deletes the one-time ephemeral private key on receiving the message.

To reduce storage costs for the intermediary, the "signed ephemeral
and extra ephemeral" variant of TripleDH can be used, so that the
intermediary only needs to store a single signed ephemeral public key,
and can store a larger number of extra ephemeral public keys without
signatures.

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

3.6. Alternatives
-

One alternative to TripleDH is to use signatures for authentication.
For example:

    1.  Alice -> Bob: A, A', Signature(A, A')
    1.  Alice <- Bob: B, B', Signature(B, B')

    ID = A || B || <data>
    SKA || SKB = KDF(DH(A', B') || ID)

    2. Alice -> Bob: AE(SKA, <data>)*
    2. Alice <- Bob: AE(SKB, <data>)*

Compared to this, TripleDH has smaller messages and doesn't require
implementing signatures (in some variants).  TripleDH is also more
robust if a single ephemeral key is compromised.  Such a compromise
only allows impersonating parties to the victim while the victim uses
that key.  But above, such a compromise also allows permanent
impersonation *of* the victim, and passive decryption of all
communications involving the compromised key.

In more complex signature-based key agreements, like [SIGMA][], each
party signs values from the other.  This adds robustness against
ephemeral key compromise, but also adds message ordering constraints
and weakens deniability.

A technique from [NAXOS][] can be used in many key agreement protocols
to protect against RNG failure.  Ephemeral private keys are generated
using a KDF to combine some RNG output with a secret key that was
generated at the same time as the identity private key (with great
care the identity private key itself can be used).  Assuming the RNG
was secure when the initial data was generated, later ephemeral
private keys will be secret even if the RNG becomes predictable
(though ephemerals may be reused if the RNG repeats).

More robustness against ephemeral-key compromise can also be achieved
at the cost of extra computation by a "QuadrupleDH" which adds `DH(A,
B)` into the KDF.  With this, compromising a single ephemeral private
key does not enable impersonation attacks, and compromising both
ephemeral private keys for a session does not decrypt it.

[HMQV][] and variants provide robustness similar to QuadrupleDH, and
have greater computational efficiency than TripleDH, but have IPR
concerns.

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

Thanks to Joseph Bonneau for detailed editorial feedback.

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

[SIGMA]: #SIGMA
<a name="SIGMA">**SIGMA:**</a>
<http://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf>

[Kudla-Paterson]: #Kudla-Paterson
<a name="Kudla-Paterson">**Kudla-Paterson:**</a>
<http://www.isg.rhul.ac.uk/~kp/ModularProofs.pdf>

[NAXOS]: #NAXOS
<a name="NAXOS">**NAXOS:**</a>
<http://research.microsoft.com/pubs/81673/strongake-submitted.pdf>

[Blake-Wilson]: #BlakeWilson
<a name="Blake-Wilson">**Blake-Wilson:**</a>
<http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.27.8493>
