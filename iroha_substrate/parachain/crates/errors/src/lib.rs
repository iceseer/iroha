#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings)]

use codec::alloc::string::{String, ToString};
use frame_support::dispatch::DispatchError;
use sp_std::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    /// Error codes
    NotEnoughTokens,
    NotEnoughReservedTokens,
    RuntimeError,
}

impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Error::NotEnoughTokens => "Not enough tokens for current operation",
            Error::NotEnoughReservedTokens => "Not enough reserved tokens for current operation",
            Error::RuntimeError => "Runtime error",
        }
    }
}

impl ToString for Error {
    fn to_string(&self) -> String {
        String::from(self.message())
    }
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        DispatchError::Module {
            index: 0,
            error: error as u8,
            message: Some(error.message()),
        }
    }
}

pub type Result<T> = sp_std::result::Result<T, Error>;
pub type UnitResult = Result<()>;
