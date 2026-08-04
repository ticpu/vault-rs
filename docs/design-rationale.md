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

## An incomplete answer is refused, not annotated

A command that could not read every record it was asked about fails outright: the exit code is the
whole interface a script has, and one that must also mean "answered, partially" cannot be acted on
without parsing prose meant for a person. Seeing the partial result is an escape hatch taken
explicitly at the call site, and its cost is documented on the flag rather than encoded in a new exit
code — a caller who did not ask for it never finds an exit code meaning something new, and one who
did has been told the status is not authoritative for that run.

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

## Every exit site prints the source chain

Handlers carrying their own exit code end the process where they are rather than returning to `main`,
so a chain printed only at the top is not printed at all for them. Whatever drops the sources renders
a refused connection, an expired server certificate and a name that does not resolve as one
indistinguishable line, leaving the operator knowing a request failed and nothing about what to
change. Errors stay typed with their causes attached on the way up; adding context is the binary's
job, and so is printing every layer of it wherever the process actually ends.

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

## A private persistent directory over a shared volatile one

When the session offers no runtime directory, the token goes to a directory only this user can reach,
accepting two costs: it outlives the session, and on a networked home it reaches shared storage. The
alternative is a predictable name under a world-writable parent, where a second user creates the
directory first and the file mode the tool sets protects nothing — worse on both counts and
unprotectable from inside the process. Because nothing expires the file, logout must unlink it and a
token found expired must be unlinked rather than left, and no third fallback gets invented when
neither directory is available.

## An unreferenced `pub` item is dead, not surface

The lib target exists so tests and the binary can share code, not because anything outside this
repository links against it; no consumer can be named for an item nothing here calls. A `pub` with no
caller is therefore dead until someone names the consumer, and a static analyzer flagging one is
reporting a fact rather than guessing. Treating it as surface preserves whichever forked, unfixed copy
of a code path happened to be marked `pub`.

## The local store is a convenience copy, not the record

Artifacts are cached locally under uniform encryption and decrypted only on request; the PKI
remains the authority, so nothing depends on the copy surviving. Encryption ignores whether a given
artifact is secret because the same store holds generated keys, and a policy branching per artifact
is one classification mistake away from writing a key in the clear.
