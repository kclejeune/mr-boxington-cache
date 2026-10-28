use crate::validation::ValidationError;

#[derive(Debug)]
pub(crate) struct Error {
    pub status: u16,
    pub message: String,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn new(status: u16, message: impl ToString) -> Self {
        Self {
            status,
            message: message.to_string(),
        }
    }
    pub fn internal(error: impl std::fmt::Display) -> Self {
        worker::console_error!("{}", error);
        Self::new(500, "internal server error")
    }
}
impl From<worker::Error> for Error {
    fn from(error: worker::Error) -> Self {
        Self::internal(error)
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::new(400, error)
    }
}
impl From<ValidationError> for Error {
    fn from(error: ValidationError) -> Self {
        if error.status == 500 {
            return Self::internal(error.message);
        }
        Self::new(error.status, error.message)
    }
}
