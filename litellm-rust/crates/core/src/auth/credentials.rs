use std::fmt;
use std::time::Instant;

use reqwest::header::HeaderName;

use super::AttemptFuture;

#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialProvenance {
    CallerSupplied,
    ForwardedHeader(HeaderName),
    EnvironmentVariable(String),
    ExternalProvider,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenLease {
    pub token: SecretString,
    pub expires_at: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenCredential {
    KnownExpiry(TokenLease),
    NoStore(SecretString),
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub trait TokenProvider: Send + Sync {
    fn token(&self) -> AttemptFuture<'_, TokenCredential>;
}
