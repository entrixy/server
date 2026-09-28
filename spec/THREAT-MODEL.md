# Threat model

This says who the system defends against, who it does not, and where the line
falls. It is deliberately specific: a promise that cannot be named is a promise
nobody can check.

## What is worth taking

The ability to open a gate. The knowledge of what a person owns and where it
is — names of objects, phone numbers, geometry of the approach corridors. The
record of when someone came and went. The list of guests, and through it the
shape of a household.

The first is the obvious prize. The rest are quieter and often worse: a log of
openings is a log of a person's life.

## The server operator, including us

**Defended.** The operator cannot open anything. The key that opens is never
sent to the server — not when it is issued, not when it is used; the server
keeps a fingerprint to find a record by and a public half to check a signature
with. Names, phone numbers, geometry, welcome texts and automation rules arrive
encrypted and stay that way: the keys to them live on the owner's phone and in
the guests' bundles. A backup of that database restores records, not the
ability to open: fingerprints and public halves cannot produce a signature. The
owner's own backup, written by the app and encrypted with their password, is a
different thing entirely — it carries the keys, and it does restore access on a
new phone.

**Not defended.** The operator sees the shape of the traffic: which key
fingerprint opened which object id, at what time, from which network. That is
routing, and routing is the server's job. They also see webhook addresses when
the owner asked the server to fire them, and they can refuse service at any
moment — a server that lies by omission is always possible.

One thing the operator must not be able to do is vouch for someone. That is why
a company's key is fetched by the phone from the company's own domain, and why
the badge of authenticity is shown only for records verified that way.

## Someone holding the link

**By design.** Whoever holds the link can open what that key allows. It is a
key, and a key works for whoever carries it. The owner limits the damage: a key
is bound to the first device that uses it, may be marked for the app only, can
be revoked at any moment, and revocation cascades to everything passed further
down the chain.

**Defended, once the key has settled.** The first handset to use a key derives
a pair of its own from the key and its hardware, and the server accepts nothing
else afterwards. The hardware half of that is the device fingerprint, which on
Android is derived from an identifier the system hands out — on a phone with
root it can be forged, and then so can the pair. The binding is as honest as
the fingerprint underneath it, which is worth more than a comparison the server
performs and less than a secret that never existed anywhere else. A link that surfaces later — photographed, forwarded, found in
a chat a year on — opens nothing, and no move to another handset can be talked
out of the server: the owner issues a new key instead.

**Not defended.** A link photographed before the guest has used it works, and
it is the copy that arrives first that settles. A key used only from a browser
never settles and stays as open as the link is. That is why the owner sees a
list of keys and a log of openings.

## Someone on the network

**Defended.** Everything travels over TLS. Requests carry a signature over the
endpoint, a timestamp, a single-use number and the body, so an intercepted
request cannot be replayed, redirected to another endpoint, or altered. The
greeting on the live connection is bound to the device fingerprint.

**Not defended.** Traffic analysis. The fact that a phone talks to a server at
a certain hour is visible to whoever carries the packets.

## Someone holding the phone

**Defended, partially.** Key material lives in encrypted storage, and the app
can be locked with a code or a fingerprint.

**Not defended.** An unlocked phone in a stranger's hands is a lost phone. The
answer is not cryptographic: the owner revokes the key, and the guest's device
loses everything at the next contact with the server.

## The guest who wants more than was given

**Defended.** The bundle contains keys only to the objects that were shared.
The server checks on every call that this key is tied to this object and that
it belongs to the owner who issued it. Passing access further is bounded by a
depth the owner sets, and the whole chain is visible to them.

## The controller

**Defended.** A network controller does not trust the server: it answers a
request with a challenge, and opens only against a signature made with a key
it knows. The server relays and cannot forge. A Bluetooth controller does not
involve the server at all.

**Not defended.** Physical access to the controller. Anyone who can reach its
wires can open the gate without any of this.

## What we do not claim

We do not claim anonymity from the server: it sees connection metadata by
construction.

We do not claim forward secrecy: a leaked link opens past bundles as well as
future ones.

We do not claim that the "app only" mark is a security boundary. The secret it
rests on is inside the installable file and can be extracted; it raises the
cost of using a stolen link in a browser, nothing more.

We do not claim protection against a hostile owner. The owner can revoke, can
see the log, can see which of their objects a guest opened. That is the point
of ownership, not a flaw.

## Where this version is weakest

Possession of the link is possession of the pair, right up until the key
settles on a handset; from then on only that handset's own pair is accepted,
and the link alone opens nothing. A key used only from a browser never settles,
and for that key the first sentence stands.

Object keys are counted by generation and can be changed — revoking a guest
changes the keys of the objects that were open to them — but the change costs
one write per remaining key, and it does not reach backwards: whatever an old
copy of the key could already read, it read.

There is one crypto suite today, named `v1`. The name is carried inside every
signature and every ciphertext and a server states which suites it speaks, so a
second one can be added without breaking what is already issued — but until
there is a second one, this line of defence is untested.

There is no forward secrecy. A link that leaks opens what was encrypted before
it leaked, not only what comes after.
