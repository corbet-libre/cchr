
Balance material: `balance-material.json` is the original public output of cblc b7449bdd32e884cfe29eff3bdbf787577bdda545, CI 36936767652, SHA-256 bb013abe6ce3e3f0e8c45481ced22e6cd099361b635af4b95c555511112e4f55. Its configuredFixtureRing is a separately supplied fictional test anchor. The activated issuer produced the material and real extension proof replay verified its artifact bindings. Tests which alter routing metadata explicitly re-sign with their test publisher; that tests feed authentication, not a new proof or record-currentness verdict.

Root-board descriptor: `root-board-public.bin` is the original public codec output
of CPSD commit `6b49131030f417e55183b438707b461b1b0e5955`, test
`independent_expiry_root_issuance_and_joint_presentation`, SHA-256
`3ae9eff512fb682f5fd4257ba3082d2eb74243878836346026d64d364e5e8b4a`. It contains
a fictional common issuer with scope `root`; it contains no holder secret.
Transport tests re-sign routing metadata with their own configured fixture signer
and preserve these bytes opaquely. They assert transport authenticity, not CPSD
scope/epoch semantics or credential validity. The Policy integration tests execute
the original CPSD decoder and those semantic checks after configured Charter.
