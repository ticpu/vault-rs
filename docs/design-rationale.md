# Design rationale

## Passthrough for the verbs this tool does not wrap

Every Vault verb the tool does not model itself is forwarded with the server address and token
already resolved. Curated commands are a layer above that surface, never a replacement for it:
reasoning about an issuance means reading role and issuer configuration no curated command
anticipates, and without a passthrough that work moves to a separately authenticated tool, where it
happens less often and with less context at hand.

## Detected attributes are read or reported absent, never inferred

Attributes come from the artifact or are reported missing; detection failure aborts rather than
falling back to the commoner case, and nothing is derived from fields that merely correlate. An
inferred value prints identically to a measured one, so a wrong guess presents as fact — a usage
derived from key-usage bits and the presence of an alternative name labels every certificate on a
client-authentication mount as its opposite. An inference worth keeping is marked as one.

## The issuing role, not the invocation, defines the issued identity

Subject, alternative names and validity come from the role for request signing, and arguments
passed on the command line can be silently inert. Output must therefore name where each field came
from rather than echo what was asked for: a caller who believes the invocation set the subject
finds out otherwise when the relying party rejects the certificate, and the only remedy then is a
fresh request from whoever holds the private key.

## Writes to a certificate authority are rehearsed; reads are not

Minting and revocation must show what they would do and ask before doing it; reads get neither.
The undo for an issuance is a revocation that has to propagate to every relying party.

## The issued identity is the report, not its serial

An issuance reports the resulting subject, usages, alternative names and validity. A serial
identifies a record, not what was decided, and withholding the identity sends the operator to
external tooling to re-derive what this tool already parsed.

## Verification takes the peer's anchor, not the issuer's own chain

The certificate authority a relying party actually loads is the input to verification. Validating
against the issuer's own hierarchy is the tempting default, since that chain is already at hand,
and it predicts nothing about acceptance. Choosing a mount is the same decision in advance.

## Austerity applies to the data stream only

Records stay machine-parseable; status and diagnostics on the secondary stream are written for a
person. Holding status to the same terseness buys nothing — nothing parses it — and leaves
operators guessing at what happened.

## Chain artifacts separate internal configuration from external handoff

Bundles meant for an external party exclude the self-signed root, and the artifact that includes it
carries a different name. A root sent outward invites installation as a system trust anchor, giving
the whole hierarchy authority over every connection that host makes. The distinction has to be
legible in the filename, or the safe artifact gets assembled by hand and the unsafe one gets
attached.

## Cached metadata carries a schema version, not just a timestamp

The cache holds what the parser concluded, not the certificate it read, so a change to any derived
field is invisible to a mount already cached: the new binary deserializes the old conclusions and
renders them faithfully, and nothing about a stale entry looks stale. A version compared on read,
discarding the file when it differs, makes such a change self-invalidating rather than dependent on
someone being told to clear it — a timestamp cannot express that an entry was produced by code that
got the answer wrong. Anything that alters a parsed or computed field has to bump it, and a suite
that exercises only the parser cannot catch a failure to.

## The local store is a convenience copy, not the record

Artifacts are cached locally under uniform encryption and decrypted only on request; the PKI
remains the authority, so nothing depends on the copy surviving. Encryption ignores whether a given
artifact is secret because the same store holds generated keys, and a policy branching per artifact
is one classification mistake away from writing a key in the clear.
