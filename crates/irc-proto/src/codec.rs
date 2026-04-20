use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::message::Message;

/// Maximum IRC line length (including \r\n).
/// RFC 2812 says 512, but many modern servers allow more.
const DEFAULT_MAX_LINE_LENGTH: usize = 8192;

/// tokio-util Codec for IRC line-based protocol.
///
/// Decodes `\r\n`-delimited lines into `Message` structs.
/// Encodes `Message` structs into `\r\n`-terminated lines.
#[derive(Debug)]
pub struct IrcCodec {
    max_line_length: usize,
    /// Tracks how far we've searched for \r\n in the buffer.
    next_search_offset: usize,
}

impl IrcCodec {
    pub fn new() -> Self {
        Self {
            max_line_length: DEFAULT_MAX_LINE_LENGTH,
            next_search_offset: 0,
        }
    }

    pub fn with_max_line_length(max_line_length: usize) -> Self {
        Self {
            max_line_length,
            next_search_offset: 0,
        }
    }
}

impl Default for IrcCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("line too long (max {max} bytes)")]
    LineTooLong { max: usize },
    #[error("invalid UTF-8 in IRC message")]
    InvalidUtf8,
    #[error("malformed IRC message")]
    MalformedMessage,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Decoder for IrcCodec {
    type Item = Message;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Search for \r\n or \n starting from where we left off
        let search_start = self.next_search_offset;

        if let Some(newline_pos) = find_line_end(&src[search_start..]) {
            let line_end = search_start + newline_pos;

            // Determine how many bytes the line terminator is (\r\n vs \n)
            let crlf_len = if line_end > 0 && src[line_end - 1] == b'\r' {
                2
            } else {
                1
            };
            let line_len = line_end + 1 - crlf_len; // content length without terminator

            // Check line length (content only)
            if line_len > self.max_line_length {
                // Consume the oversized line and report error
                src.advance(line_end + 1);
                self.next_search_offset = 0;
                return Err(CodecError::LineTooLong {
                    max: self.max_line_length,
                });
            }

            // Extract the line content (without \r\n)
            let line_content = if crlf_len == 2 {
                &src[..line_end - 1]
            } else {
                &src[..line_end]
            };

            let line_str =
                std::str::from_utf8(line_content).map_err(|_| CodecError::InvalidUtf8)?;

            let msg = Message::parse(line_str);

            // Consume the full line including terminator
            src.advance(line_end + 1);
            self.next_search_offset = 0;

            match msg {
                Some(m) => Ok(Some(m)),
                None => {
                    // Empty or unparseable line — skip and try next
                    self.decode(src)
                }
            }
        } else {
            // No complete line yet — check if buffer is getting too large
            if src.len() > self.max_line_length {
                return Err(CodecError::LineTooLong {
                    max: self.max_line_length,
                });
            }
            self.next_search_offset = src.len();
            Ok(None)
        }
    }
}

impl Encoder<Message> for IrcCodec {
    type Error = CodecError;

    fn encode(&mut self, msg: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let s = msg.to_string();
        dst.reserve(s.len() + 2);
        dst.put_slice(s.as_bytes());
        dst.put_slice(b"\r\n");
        Ok(())
    }
}

/// Also allow encoding raw string messages.
impl Encoder<String> for IrcCodec {
    type Error = CodecError;

    fn encode(&mut self, msg: String, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(msg.len() + 2);
        dst.put_slice(msg.as_bytes());
        dst.put_slice(b"\r\n");
        Ok(())
    }
}

/// Find the position of the first `\n` in the slice.
fn find_line_end(buf: &[u8]) -> Option<usize> {
    memchr::memchr(b'\n', buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_line() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::from("NICK foo\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, crate::command::Command::Nick);
        assert_eq!(msg.params, vec!["foo"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_partial() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::from("NICK fo");
        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(b"o\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.params, vec!["foo"]);
    }

    #[test]
    fn decode_multiple() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::from("NICK a\r\nNICK b\r\n");
        let msg1 = codec.decode(&mut buf).unwrap().unwrap();
        let msg2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg1.params, vec!["a"]);
        assert_eq!(msg2.params, vec!["b"]);
    }

    #[test]
    fn decode_lf_only() {
        let mut codec = IrcCodec::new();
        let mut buf = BytesMut::from("NICK foo\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.params, vec!["foo"]);
    }

    #[test]
    fn encode_message() {
        let mut codec = IrcCodec::new();
        let msg = Message::new(
            crate::command::Command::Privmsg,
            vec!["#test".into(), "hello world".into()],
        );
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        assert_eq!(&buf[..], b"PRIVMSG #test :hello world\r\n");
    }
}
