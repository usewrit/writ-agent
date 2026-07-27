use byteorder::{BigEndian, WriteBytesExt};

/// Utilities for encoding screencast frames into the binary wire format
/// expected by the frontend.
///
/// The actual CDP screencast lifecycle (start/stop/ack) is managed by
/// `recorder::core::PlaywrightRecorder::screenshot_loop_cdp`, which calls
/// `encode_frame` directly.  This struct exists only as a namespace for
/// the frame encoding helper.
pub struct ScreencastStream;

impl ScreencastStream {
    /// Encode a screenshot frame into the binary wire format.
    ///
    /// Layout: `[4 bytes BE url_len][url UTF-8 bytes][JPEG bytes]`
    ///
    /// This matches the Python recorder's binary frame format so the
    /// frontend can decode frames identically.
    pub fn encode_frame(url: &str, jpeg_data: &[u8]) -> Vec<u8> {
        let url_bytes = url.as_bytes();
        let mut buf = Vec::with_capacity(4 + url_bytes.len() + jpeg_data.len());

        // 4-byte big-endian URL length
        buf.write_u32::<BigEndian>(url_bytes.len() as u32)
            .expect("vec write cannot fail");

        // URL bytes
        buf.extend_from_slice(url_bytes);

        // Raw JPEG data
        buf.extend_from_slice(jpeg_data);

        buf
    }

    /// Fast FNV-1a hash of a JPEG payload, used to skip transmitting frames that
    /// are byte-identical to the previously sent one (static page → no new bytes
    /// on the wire). Identical bytes ⇒ identical pixels, so skipping is always
    /// safe; differing bytes for identical pixels just means we send (correct,
    /// only slightly less optimal).
    pub fn frame_hash(jpeg_data: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in jpeg_data {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_frame() {
        let url = "https://example.com";
        let jpeg = b"\xFF\xD8\xFF\xE0fake_jpeg";
        let encoded = ScreencastStream::encode_frame(url, jpeg);

        // First 4 bytes = big-endian URL length
        let url_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(url_len, url.len());

        // Next url_len bytes = URL
        let decoded_url = std::str::from_utf8(&encoded[4..4 + url_len]).unwrap();
        assert_eq!(decoded_url, url);

        // Remainder = JPEG data
        assert_eq!(&encoded[4 + url_len..], jpeg);
    }

    #[test]
    fn test_encode_frame_empty_url() {
        let url = "";
        let jpeg = b"\xFF\xD8";
        let encoded = ScreencastStream::encode_frame(url, jpeg);
        let url_len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(url_len, 0);
        assert_eq!(&encoded[4..], jpeg.as_slice());
    }
}
