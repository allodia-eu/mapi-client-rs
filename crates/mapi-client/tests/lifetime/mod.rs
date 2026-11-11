//! A Session Context over time, against the server that times it out.
//!
//! Part of `tests/live.rs`. Only the quick questions are here — what a response says about a
//! context's lifetime, and that a `PING` moves it. Idling past that lifetime takes a quarter of an
//! hour on Exchange, which is longer than this whole suite is worth waiting for.

/// A request given up on part way, and the disconnect that has to work afterwards.
mod cancellation;

/// What a context's lifetime is, and that a `PING` restarts it.
mod expiry;
