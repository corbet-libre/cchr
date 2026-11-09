//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` that the host runs is a module here, so a warm edit loop
//! links one test executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). `door` stays separate: its tier needs the `.build/fixtures` the
//! door-fixtures CI gate generates.
mod birth_genesis;
mod genesis_stamp;
mod mutant_kills_mut123;
mod passkeys;
mod revision_stamp;
mod root_board;
mod snapshot_age;
mod vectors;
