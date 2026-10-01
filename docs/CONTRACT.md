# Charter contract as implemented

Charter is an LGPL device/server consumer of the existing cvld/cplc trust feed.
It verifies public community material; it does not decide admission or store
member activity. csgn verifies signatures; cshm checks schema semantics.

## API and trust boundary

`Charter::new(origin, community)` binds one exact normalized HTTPS origin and
community. Userinfo, query, fragment, non-root paths and HTTP are refused.
`AuthenticatedOrigin::from_authenticated_response` is a privileged port: only a
trusted adapter which authenticated that origin, or authenticated configuration,
may assert its ring, current revision floor, observation time and exclusive
receipt deadline. Untrusted bytes cannot establish their own authority. An
origin assertion is valid only from its observation time through its deadline.
A fresh TLS request must bypass caches and redirects. Network timing anonymity
and authenticating a compromised server are not claims of this type.

`install(bytes, authority, now)` checks the original cvld JSON envelope and all
six COSE objects: manifest plus settings, schema, schema_versions, communities,
revocations. It returns an immutable `VerifiedCharter` only after all checks.
`current(now)` checks expiry and the clock high-water mark on every read.
`changes_since(revision, now)` returns Unchanged or Replace for the whole current
set, never a persisted event history; future cursors fail.

The view exposes original signed bytes, revision, effective policy epoch,
minimum signed deadline, verification ring, schema, checked classifications and
revocation membership queries. It is not serializable or caller-constructible.
Keep references within the current operation: extracted bytes or a ring are not
permanent admission authority. The sole admitting owner must check freshness.

## States and atomicity

Unbootstrapped → synchronous Verifying → Current. Expiry, absent material or
clock regression yields Unavailable. Invalid candidates do not change installed
material or floors. Valid old material remains readable after a failed install
until its original deadline. Expiry never deletes floors; subsequent refreshes
must still advance or exactly reproduce retained revisions. Time is a supplied
Unix-second value; any observation advances a high-water mark. A regressed clock
is refused until it catches up, including after reading an expired view.

Installation prepares and validates all content before replacing one owned
in-memory value. There is no partial commit, storage conflict or uncertain I/O
outcome in this pure leaf. A new instance has no authority; forum restart requires
a fresh authenticated origin/floor source. Device persistence belongs only in an
encrypted vault adapter and is not implemented here.

## Formats, floors and limits

Consume cvld's existing JSON byte arrays without re-signing or rewriting COSE.
The manifest requires `cplc.trust.v1`, exact community, ring, positive revision,
effective epoch and current schema version. Every snapshot requires its protected
csgn purpose, same community and epoch, positive per-kind revision no greater
than the manifest revision. csgn enforces canonical COSE and all signature times.
Schema history requires `cplc.schema-versions.v1`, ordered valid schemas ending
in the exact current schema; cshm must reproduce every predecessor classification.
Archives never authorize grandfathering. Settings remain the full authenticated
JSON map; no gate semantics are discarded. Separate revocations always install.

Manifest and per-kind revisions and epoch never regress in a running instance.
Equal revision with different signed bytes is equivocation, including refreshed
signature timestamps. An equal manifest revision cannot replace any snapshot.
A new ring requires new authenticated origin evidence; retained keys continue to
verify according to csgn. No signature by the candidate ring authenticates that
ring. The producer's manifest does not include snapshot hashes: coherent delivery
also relies on authenticated origin transport, alongside scope/epoch/schema and
monotonic checks. This consumer does not invent a new manifest version.

Hard implementation bounds: 32 MiB transport JSON (accounts for integer arrays),
1 MiB + 8192 bytes per COSE snapshot, csgn's 1 MiB payload/256 KiB ring bounds,
256 schema versions and community-directory entries, serde's bounded nesting.
Duplicate object fields at every depth, unknown typed envelope fields, missing
kinds, malformed values and trailing data fail. These caps refuse unsupported
size; they never silently truncate. Errors and Debug contain fixed categories,
never origin/community/member values or dependency diagnostics.

## Acceptance and remaining seam

Shared native/wasm vectors cover signed corruption, wrong purpose/scope, mixed
epochs, missing kinds, rollback, exact-byte conflict, duplicate fields, expiry,
clock regression, bootstrap freshness, authorized rotation/retained keys and a
bounded 200-consumer install/update load. The real-door job uses the pinned cvld
source named in `scripts/door-fixtures.sh`, temporary libSQL services and real
WebAuthn/BBS flows. All/any/k-of-n policy edits, schema publication and last-passkey
revocation use the HTTP registry, and ordinary registration/lobby traffic must
leave trust bytes unchanged. Identical captured bytes execute natively and in wasm.

`admission_policy(action, now, maximum_snapshot_age)` borrows the original signed
settings and separate revocations for `cgrd::check_published`. It refuses expired
Charters and transfers authenticated revision/epoch floors without serializing
replacement settings. The schema bytes come from `publication(Kind::Schema)`.
The trusted caller selects the Rulebook action. Merely constructing this adapter
never admits anyone: Guard requires signed credential/device/profile/pin evidence
and invokes the complete portable Rulebook evaluator. Policies requiring global
or proof-time evidence absent from cplc credentials refuse; no authority is
invented. Device-authority issuance at the door remains the G3 integration seam.
Operational TLS bootstrap and encrypted device floor persistence remain caller
responsibilities. No full cmeet/Tor acceptance is implied.

Archived schema definitions and their classifications are immutable across
installs. Every previously retained version must remain present, byte-equivalent
as typed schema/classification data; the current schema version cannot regress.
