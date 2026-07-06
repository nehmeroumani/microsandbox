//! Configuration for [`VirtualFs`](super::VirtualFs).

use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cache policy for FUSE open options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// No caching — sets `DIRECT_IO`.
    Never,
    /// Let the kernel decide.
    Auto,
    /// Aggressive caching — sets `KEEP_CACHE`/`CACHE_DIR`.
    Always,
}

/// Configuration for a [`super::VirtualFs`].
#[derive(Debug, Clone)]
pub struct VirtualFsConfig {
    /// FUSE entry cache timeout.
    pub entry_timeout: Duration,
    /// FUSE attribute cache timeout.
    pub attr_timeout: Duration,
    /// Cache policy.
    pub cache_policy: CachePolicy,
    /// Enable writeback caching.
    pub writeback: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for VirtualFsConfig {
    fn default() -> Self {
        Self {
            entry_timeout: Duration::from_secs(1),
            attr_timeout: Duration::from_secs(1),
            cache_policy: CachePolicy::Auto,
            writeback: false,
        }
    }
}
