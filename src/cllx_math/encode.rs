// cllX-Math: Lossless encoding layer
// Converts bytes <-> u32 polynomials

use crate::core::Result;

/// Encode chunk bytes to u32 polynomial (4 bytes -> 1 u32)
pub fn encode_chunk(chunk: &[u8]) -> Vec<u32> {
    chunk
        .chunks(4)
        .map(|bytes| {
            let mut arr = [0u8; 4];
            arr[..bytes.len()].copy_from_slice(bytes);
            u32::from_le_bytes(arr)
        })
        .collect()
}

/// Decode u32 polynomial back to bytes
pub fn decode_chunk(poly: &[u32]) -> Vec<u8> {
    poly.iter()
        .flat_map(|&val| val.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = b"Hello, cllX-FS! This is a test message.";
        let poly = encode_chunk(original);
        let decoded = decode_chunk(&poly);
        
        assert_eq!(&decoded[..original.len()], original);
    }

    #[test]
    fn test_encode_decode_random() {
        let original: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let poly = encode_chunk(&original);
        let decoded = decode_chunk(&poly);
        
        assert_eq!(decoded[..original.len()], original[..]);
    }
}
