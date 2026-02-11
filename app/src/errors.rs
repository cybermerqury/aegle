use std::error::Error;
use std::fmt::{Debug, Display};

pub type SubsystemResult = Result<(), SubsystemError>;
pub type MainResult<T> = Result<T, Box<dyn MainError>>;

#[derive(Debug)]
pub struct SubsystemError(pub String);

impl Display for SubsystemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error in a subsystem: {}", self.0)
    }
}

impl From<tokio::task::JoinError> for SubsystemError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self(format!("{}", value))
    }
}

impl From<std::io::Error> for SubsystemError {
    fn from(value: std::io::Error) -> Self {
        Self(format!("{}", value))
    }
}

impl From<Box<dyn MainError>> for SubsystemError {
    fn from(value: Box<dyn MainError>) -> Self {
        Self(format!("{:?}", value))
    }
}

impl Error for SubsystemError {}

struct MainErrorStruct<E>
where
    E: Error,
{
    inner: E,
}

impl<E> From<E> for Box<dyn MainError>
where
    E: Error + Sync + Send + 'static,
{
    fn from(value: E) -> Self {
        Box::new(MainErrorStruct { inner: value })
    }
}

pub struct ErrorMessage<S>(pub S)
where S: AsRef<str> + Debug + Display;

impl<S> Debug for ErrorMessage<S>
where S: Display + Debug + AsRef<str>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl<S> Display for ErrorMessage<S>
where S: AsRef<str> + Debug + Display
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

impl<S> Error for ErrorMessage<S>
where S: AsRef<str> + Debug + Display
{}

impl<E> Debug for MainErrorStruct<E>
where
    E: Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error in main: {:?}", self.inner)
    }
}

pub trait MainError: Debug + Sync + Send {}

impl<E> MainError for MainErrorStruct<E> where E: Error + Sync + Send {}
