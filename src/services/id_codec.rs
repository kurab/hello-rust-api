/*
 * Responsibility
 * - 公開 ID ↔ 内部 ID の変換 (encode/decode)
 * - ハッシュ / 暗号 / 署名などの実装をここに閉じ込める
 * - Extractor や DTO からはこの service を使う (方式変更の影響を局所化)
 */
use anyhow::{Result, anyhow};
use sqids::{Error as SqidsError, Sqids};

#[derive(Clone, Debug)]
pub struct IdCodec {
    sqids: Sqids,
}

#[derive(Debug)]
pub enum DecodeIdError {
    InvalidFormat,
    OutOfRange,
}

impl IdCodec {
    pub fn new(min_length: usize, alphabet: &str) -> Result<Self> {
        let min_length: u8 = min_length
            .try_into()
            .map_err(|_| anyhow!("SQIDS_MIN_LENGTH must be between 0 and 255"))?;

        let sqids = Sqids::builder()
            .min_length(min_length)
            .alphabet(alphabet.chars().collect())
            .build()
            .map_err(|e: SqidsError| anyhow!(e))?;

        Ok(Self { sqids })
    }

    pub fn encode(&self, id: i64) -> Result<String> {
        if id < 0 {
            return Err(anyhow!("id must be non-negative"));
        }
        let n = id as u64;
        self.sqids.encode(&[n]).map_err(|e: SqidsError| anyhow!(e))
    }

    pub fn decode(&self, public_id: &str) -> Result<i64, DecodeIdError> {
        let nums = self.sqids.decode(public_id);
        if nums.len() != 1 {
            return Err(DecodeIdError::InvalidFormat);
        }
        i64::try_from(nums[0]).map_err(|_| DecodeIdError::OutOfRange)
    }
}
