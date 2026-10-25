# Charter contract as implemented

Charter is an LGPL device/server consumer of the existing cvld/cplc trust feed.
It verifies public community material; it does not decide admission or store
member activity. csgn verifies signatures; cshm checks schema semantics.

## API and trust boundary

`Charter::new(Configuration)` binds trusted per-community deployment configuration:
exact normalized HTTPS origin, community, public root ring, positive minimum feed
revision and nondecreasing ring-only transition revision. Userinfo, query,
fragment, non-root paths and HTTP are refused. The root issuer must match the
community. The configuration must never come from a response or member request.
`origin()` exposes the canonical configured origin for transport adapters.

`install(bytes, now)` accepts original public bytes and injected Unix seconds.
It verifies original csgn KeyRingTransition proofs using the currently installed
ring before any candidate ring can verify a manifest. Each new proof binds the
exact predecessor/successor rings and its ring-only revision; mismatched claimed
revision, nonincreasing new revisions, self-transition or missing continuity
refuse. Older retained proofs at or below the installed floor are ignored and
confer no authority. After all proofs, the resulting ring must exactly equal the
feed's ring. A valid TLS connection cannot authorize a forged root.

The complete candidate includes the original manifest and five snapshots:
settings, schema, schema_versions, communities and separate revocations. Ring
changes, floors and all publications commit together only after every check.
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
trusted deployment roots/floors and a fresh signed publication. Device persistence belongs only in an
encrypted vault adapter and is not implemented here.

## Formats, floors and limits

Consume cvld's existing JSON byte arrays without re-signing or rewriting COSE.
The manifest requires `cplc.trust.v1`, exact community, ring, positive revision,
effective epoch and current schema version. Every snapshot requires its protected
csgn purpose, same community and epoch, positive per-kind revision no greater
than the manifest revision. csgn enforces canonical COSE and all signature times.
Schema history requires `cplc.schema-versions.v1`, ordered valid schemas ending
in the exact current schema; cshm must reproduce every predecessor classification.
Its classify_changes requires each successor version to be strictly greater,
so repeated and decreasing versions fail before any archive is installed.
Archives never authorize grandfathering. Settings remain the full authenticated
JSON map; no gate semantics are discarded. Separate revocations always install.

Manifest and per-kind revisions and epoch never regress in a running instance.
Equal revision with different signed bytes is equivocation, including refreshed
signature timestamps. An equal manifest revision cannot replace any snapshot.
Every later ring requires signed continuity from the installed ring; retained
keys continue to verify according to csgn. No signature by a candidate ring
authenticates that ring. Optional `key_transitions` carries ordered objects with
public `revision` and original COSE `proof` bytes. At most256 retained transitions
fit within the existing total transport bound. Ring revisions advance only for
ring changes, never for ordinary signing/reopen activity. A missing or expired
required proof fails closed; reconfiguration is an explicit deployment action. The producer's manifest does not include snapshot hashes: coherent delivery
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
clock regression, configured roots, signed rotation/retained keys and a
bounded 200-consumer install/update load. The real-door job fetches cvld main,
resolves one coherent branch-main dependency graph, and retains the exact source
revision, metadata and Cargo.lock as evidence. It uses temporary libSQL services and real
WebAuthn/BBS flows. All/any/k-of-n policy edits, schema publication and last-passkey
revocation use the HTTP registry, and ordinary registration/lobby traffic must
leave trust bytes unchanged. Identical captured bytes execute natively and in wasm.

`current_admission_policy(action, now)` is `admission_policy` with the one product limit
`MAXIMUM_SNAPSHOT_AGE` = 2 UTC days (code constant, never configuration; staleness is bounded by the signed
validity). `admission_policy(action, now, maximum_snapshot_age)` borrows the original signed
settings and separate revocations for `cgrd::check_published`. It refuses expired
Charters and transfers authenticated revision/epoch floors without serializing
replacement settings. The schema bytes come from `publication(Kind::Schema)`.
The trusted caller selects the expected issuance action. The adapter forwards it
as Guard's required `Policy.expected_issuance_action`, independently of all member
input. Merely constructing this adapter never admits anyone: Guard requires the
current signed v2 issuer admission decision bound to that exact action and epoch,
plus the original device/profile/pin and revocation evidence. Private global proofs
and proof times stay at the issuer. Missing v2 purpose or action, a different action,
and old-epoch credentials refuse; renewal follows the issuer's explicit epoch
migration. This does not provide the separate mandatory G2 accounting authority.
Device-authority issuance at the door remains the G3 integration seam.
Operational TLS and encrypted device floor persistence remain caller
responsibilities. No full cmeet/Tor acceptance is implied.

Archived schema definitions and their classifications are immutable across
installs. Every previously retained version must remain present, byte-equivalent
as typed schema/classification data; the current schema version cannot regress.

## Balance snapshot

The signed manifest may require a canonical Balance document through
`balance_revision`. Its separate `balance` feed field must then be present with
the exact revision, same community/epoch and strict
`cblc.public-verifier.v2` purpose under the configured publication ring. It is
installed atomically with all other snapshots and key transitions; its deadline
shortens the whole view. Missing, regressed or conflicting bytes refuse and
retain the old floors, including after expiry. A configured kind cannot later
disappear. Duplicate payload fields are rejected at every depth.

`VerifiedCharter::balance()` borrows original authenticated bytes and routing
metadata via Beacon's shared `balance::Balance` type. Decode economic policy and
artifact bindings with the accounting owner; this LGPL library introduces no
second accounting schema, account-state verifier or FSL dependency. An absent
Balance document grants no accounting capability. Public-record currentness and
punishment remain separate feature decisions.

## Passkey verification material

`VerifiedCharter::passkey_binding(original_cose, expected_member, now)` uses the
original Policy ring and strict duplicate-key decoder to authenticate purpose
`cplc.passkey-lineage.v1`, exact community/member/epoch, original Keyhole descriptor
and current member/credential-ID revocations. The signed revocation set must
explicitly contain `passkeys`; legacy absence is Unavailable. The borrowed
`VerifiedPasskeyBinding` retains exact COSE, original typed descriptor and the
minimum of envelope/complete-publication deadlines. `credential(now)` checks
issuance and expiry again. This verifies public material, not possession,
admission, a fresh session or a lineage change. G3 owners retain those checks and
must obtain the current Foyer/Charter after every authority await.
