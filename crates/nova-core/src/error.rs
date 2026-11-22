//! Erreur unique de l'outil : un message lisible, avec son contexte.

use std::fmt;

/// Erreur rapportée à l'utilisateur.
#[derive(Debug)]
pub struct Error(String);

/// Résultat de l'outil.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Construit une erreur depuis un message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Ajoute à une erreur ce qu'on était en train de faire.
pub trait Context<T> {
    /// Préfixe l'erreur par `what`.
    fn context(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|error| Error(format!("{} : {error}", what())))
    }
}
