// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

#[macro_export]
macro_rules! generate_uuid_newtype {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            serde::Deserialize,
            serde::Serialize,
            Hash,
        )]
        pub struct $name(uuid::Uuid);

        /// Newtype wrapper around a UUID
        impl $name {
            pub const fn new(uuid: uuid::Uuid) -> Self {
                Self(uuid)
            }

            pub fn new_v4() -> Self {
                Self(uuid::Uuid::new_v4())
            }

            /// An explicitly typed conversion to [`Uuid`].
            pub fn uuid(&self) -> uuid::Uuid {
                self.0
            }
        }

        impl From<uuid::Uuid> for $name {
            fn from(value: uuid::Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for uuid::Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid = uuid::Uuid::from_str(s)?;

                Ok(Self(uuid))
            }
        }

        impl AsRef<uuid::Uuid> for $name {
            fn as_ref(&self) -> &uuid::Uuid {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
