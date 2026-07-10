//! axiom-core: pure client-side logic for the Axiom proxy — E2EE, TEE attestation verification,
//! the relay client, and OpenAI-compatible types. No axum, no Tauri; unit-testable in isolation.

pub mod attestation;
pub mod config;
pub mod e2ee;
pub mod error;
pub mod events;
pub mod openai;
pub mod provider;
pub mod providers;
pub mod relay;

pub use config::Config;
pub use error::{CoreError, Result};
