pub mod control;
pub mod db;
pub mod relay;

use std::sync::Arc;

/// Secret shared by the control server and its relays. Signs tickets and
/// authenticates relay registration.
pub type SharedSecret = Arc<Vec<u8>>;
