//! Bound peer-controlled question allocation before decoding DNS replies.

use std::io;

use hickory_proto::op::Message;

pub(crate) fn decode_answer(bytes: &[u8]) -> io::Result<Message> {
    // RFC 9619 section 4 limits QUERY messages to zero or one question.
    // Our callers additionally match the one question they sent. Preserve
    // their treatment of zero-question replies, but reject excessive counts
    // before Hickory's Message::read reserves a vector of that size.
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed DNS answer");
    if bytes.len() < 12 || u16::from_be_bytes([bytes[4], bytes[5]]) > 1 {
        return Err(invalid());
    }
    Message::from_vec(bytes).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excessive_question_counts_and_short_headers_are_rejected() {
        for count in [2u16, u16::MAX] {
            let mut header = [0; 12];
            header[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            header[4..6].copy_from_slice(&count.to_be_bytes());
            assert_eq!(decode_answer(&header).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        for length in 0..12 {
            assert!(decode_answer(&[0; 12][..length]).is_err());
        }
    }

    #[test]
    fn zero_question_replies_remain_decodable_for_transaction_matching() {
        let response = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
        let answer = decode_answer(response).unwrap();
        assert_eq!(answer.metadata.id, 0x1234);
        assert!(answer.queries.is_empty());
    }
}
