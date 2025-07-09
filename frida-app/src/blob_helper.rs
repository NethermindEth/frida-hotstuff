use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;

pub struct YodaBlobData(pub Bytes);

impl YodaBlobData {
    pub fn from_raw(raw: Bytes) -> Result<Self, Error> {
        // if raw.len() < APP_ID_LENGTH {
        //     return Err(Error::Error);
        // }
        Ok(Self(raw))
    }
}

/// u64 blob length prefix.
const PREFIX_BYTES_NUM: usize = size_of::<u64>();

/// Blobs are concatenated together, each blob prefixed by u64 blob length:
/// <pre> length1 blob1 length2 blob2 ... </pre>
pub fn merge_blobs(yoda_blobs: &[YodaBlobData]) -> Bytes {
    let mut buf = BytesMut::with_capacity(
        yoda_blobs
            .iter()
            .map(|b| PREFIX_BYTES_NUM + b.0.len())
            .sum(),
    );

    for yoda_blob in yoda_blobs.iter() {
        let raw = &yoda_blob.0;
        buf.put_u64(raw.len() as u64);
        buf.put(raw.clone());
    }

    buf.freeze()
}

/// Unmerge the previously merged blob.
pub fn unmerge_blobs(merged_blob: &Bytes) -> Result<Vec<YodaBlobData>, Error> {
    let mut result = vec![];

    let mut merged = merged_blob.clone();
    while !merged.is_empty() {
        if merged.len() < PREFIX_BYTES_NUM {
            return Err(Error::Error);
        }
        let blob_len = merged.get_u64() as usize;
        if merged.len() < blob_len {
            return Err(Error::Error);
        }
        let yoda_blob = YodaBlobData::from_raw(merged.slice(..blob_len))?;
        result.push(yoda_blob);
        merged.advance(blob_len);
    }

    Ok(result)
}