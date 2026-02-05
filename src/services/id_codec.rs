/*
 * Responsibility
 * - 公開 ID ↔ 内部 ID の変換 (encode/decode)
 * - ハッシュ / 暗号 / 署名などの実装をここに閉じ込める
 * - Extractor や DTO からはこの service を使う (方式変更の影響を局所化)
 *
 * thiserror を使わない理由:
 * - このモジュール内で完結するエラー型なので
 * - 外部に公開する必要がないので
 */
use sqids::{Error as SqidsError, Sqids};
use std::{error::Error, fmt};

pub type Result<T> = std::result::Result<T, IdCodecError>;

#[derive(Debug)]
pub enum IdCodecError {
    InvalidMinLength { value: usize },
    Sqids(SqidsError),
    NegativeId { value: i64 },
    DecodeInvalidFormat,
    DecodeOutOfRange,
}

impl fmt::Display for IdCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdCodecError::InvalidMinLength { value } => {
                write!(
                    f,
                    "SQIDS_MIN_LENGTH must be between 0 and 255, got {}",
                    value
                )
            }
            IdCodecError::Sqids(e) => write!(f, "Sqids error: {}", e),
            IdCodecError::NegativeId { value } => {
                write!(f, "id must be non-negative, got {}", value)
            }
            IdCodecError::DecodeInvalidFormat => {
                write!(f, "invalid public id format")
            }
            IdCodecError::DecodeOutOfRange => {
                write!(f, "decoded id is out of range")
            }
        }
    }
}

impl Error for IdCodecError {}

impl From<SqidsError> for IdCodecError {
    fn from(e: SqidsError) -> Self {
        IdCodecError::Sqids(e)
    }
}

#[derive(Clone, Debug)]
pub struct IdCodec {
    sqids: Sqids,
}

impl IdCodec {
    pub fn new(min_length: usize, alphabet: &str) -> Result<Self> {
        let min_length: u8 = min_length
            .try_into()
            .map_err(|_| IdCodecError::InvalidMinLength { value: min_length })?;

        let sqids = Sqids::builder()
            .min_length(min_length)
            .alphabet(alphabet.chars().collect())
            .build()
            .map_err(IdCodecError::from)?;

        Ok(Self { sqids })
    }

    pub fn encode(&self, id: i64) -> Result<String> {
        if id < 0 {
            return Err(IdCodecError::NegativeId { value: id });
        }
        let n = id as u64;
        self.sqids.encode(&[n]).map_err(IdCodecError::from)
    }

    pub fn decode(&self, public_id: &str) -> Result<i64> {
        let nums = self.sqids.decode(public_id);
        if nums.len() != 1 {
            return Err(IdCodecError::DecodeInvalidFormat);
        }
        i64::try_from(nums[0]).map_err(|_| IdCodecError::DecodeOutOfRange)
    }
}
