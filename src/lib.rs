mod attestation;
mod conn;
pub mod scallop;

pub use attestation::{decode_attestation, get_attestation_doc, verify};
pub use conn::{MolluskError, MolluskStream};
