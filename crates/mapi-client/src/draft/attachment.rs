//! One attachment of an item being created, and the two round trips that are not one.
//!
//! Split from the message it hangs off because the object model does: an Attachment object is
//! created, filled and committed on its own, *before* the message that holds it is saved
//! ([MS-OXCPRPT] §3.1.4.16). Getting that order backwards loses the attachment without failing.
//!
//! The other reason is the content. A message's properties go out in one `RopSetProperties`; an
//! attachment's bytes go through a stream, and a stream write is bounded by a two-byte length
//! field — so this is where the chunking loop lives, and where the handles it opens have to be
//! given back on the way out of a failure as well as a success.

use mapi_proto::{
    AttachMethod, AttachmentNumber, ObjectHandle, PropertyProblem, PropertyTag, PropertyValue,
    RopBatch, RopResponse, StreamMode, TaggedValue,
};

use crate::connection::Connection;
use crate::error::{Error, Result};

/// Bytes per `RopWriteStream`.
///
/// Unlike the read side, the limit here is documented and needs no measurement: `DataSize` is two
/// bytes ([MS-OXCROPS] §2.2.9.3.1) and the ROP list that carries the write is itself bounded by a
/// two-byte `RopSize` that counts every ROP in the buffer ([MS-OXCROPS] §2.2.1). 16 KiB leaves room
/// for the rest of the batch under both, and matches what the read path asks for — so a value
/// written here and read back travels in the same number of pieces.
const WRITE_CHUNK: usize = 16 * 1024;

/// An attachment to create, with the bytes that will become its content.
///
/// Held in memory rather than streamed from a reader, because the size that matters is the one the
/// mailbox will hold: an attachment is a property value, and a caller that cannot fit it in memory
/// cannot send it here either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAttachment {
    properties: Vec<TaggedValue>,
    content: Vec<u8>,
}

impl NewAttachment {
    /// An ordinary file attachment — `PidTagAttachMethod` of `afByValue`.
    ///
    /// Sets the method, both file names, the extension and the display name from `file_name`. The
    /// extension is taken from the name rather than from the content, which is what every other
    /// client does and is worth knowing: an attachment called `notes.txt` holding a PDF says `.txt`
    /// here and the receiving client believes it.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the name holds an interior NUL, which would end its own field early
    /// and shift every field after it.
    ///
    /// [MS-OXCMSG] §2.2.2.9 — `PidTagAttachMethod`
    /// [MS-OXCMSG] §2.2.2.10 — `PidTagAttachLongFilename`
    pub fn by_value(file_name: &str, content: impl Into<Vec<u8>>) -> Result<Self> {
        let extension = file_name
            .rfind('.')
            .and_then(|at| file_name.get(at..))
            .unwrap_or_default();

        Ok(Self {
            properties: vec![
                TaggedValue::new(
                    PropertyTag::ATTACH_METHOD,
                    PropertyValue::Integer32(AttachMethod::ByValue.as_u32()),
                )?,
                TaggedValue::new(
                    PropertyTag::ATTACH_LONG_FILENAME,
                    PropertyValue::String(file_name.into()),
                )?,
                TaggedValue::new(
                    PropertyTag::ATTACH_FILENAME,
                    PropertyValue::String(file_name.into()),
                )?,
                TaggedValue::new(
                    PropertyTag::ATTACH_EXTENSION,
                    PropertyValue::String(extension.into()),
                )?,
                TaggedValue::new(
                    PropertyTag::DISPLAY_NAME,
                    PropertyValue::String(file_name.into()),
                )?,
            ],
            content: content.into(),
        })
    }

    /// Adds properties — a MIME type, a content id, anything [MS-OXCMSG] §2.2.2 names.
    #[must_use]
    pub fn set<I>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = TaggedValue>,
    {
        self.properties.extend(values);
        self
    }

    /// The bytes that will become the content.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Creates the attachment on an open message and commits it.
    ///
    /// One round trip for the attachment and its first 16 KiB, then one more per chunk after that.
    /// The stream is opened [`Create`](StreamMode::Create), which is the only mode that works on a
    /// property nothing has ever set — and every property of an attachment created moments ago is
    /// one of those.
    pub(super) async fn write(
        self,
        connection: &mut Connection,
        message: ObjectHandle,
    ) -> Result<(AttachmentNumber, Vec<PropertyProblem>)> {
        let mut chunks = self.content.chunks(WRITE_CHUNK);
        let first = chunks.next().unwrap_or_default();

        let mut batch = RopBatch::new();
        let message_slot = batch.bind(message);
        let attachment = batch.create_attachment(message_slot);
        batch.set_properties(attachment, &self.properties);
        let stream = batch.open_stream(
            attachment,
            PropertyTag::ATTACH_DATA_BINARY,
            StreamMode::Create,
        );
        batch.write_stream(stream, first);

        let execution = connection.execute(batch, "creating an attachment").await?;

        // The handles are taken before anything is checked, so that every path out from here can
        // give them back. A check that ran first would have nothing left to name.
        let (Some(stream_handle), Some(attachment_handle)) = (
            execution.handle(stream).filter(|h| !h.is_none()),
            execution.handle(attachment).filter(|h| !h.is_none()),
        ) else {
            return Err(Error::Unexpected {
                expected: "handles for the new attachment and its content stream",
                found: "no handles in the batch's responses",
            });
        };

        let filled = fill(connection, &execution, stream_handle, first, chunks).await;
        let finished = finish(connection, stream_handle, attachment_handle, filled.is_ok()).await;
        filled?;
        finished?;

        let number = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_created_attachment)
            .map(mapi_proto::CreateAttachmentResponse::number)
            .ok_or(Error::Unexpected {
                expected: "a RopCreateAttachment response",
                found: "no new attachment in the batch's responses",
            })?;
        let problems = execution
            .property_problems()
            .map(|response| response.problems().to_vec())
            .unwrap_or_default();

        Ok((number, problems))
    }
}

/// Checks the first chunk landed, then sends every chunk after it.
///
/// Separate from [`finish`] so that both run: content that did not all arrive still left an
/// attachment and a stream open behind it.
async fn fill(
    connection: &mut Connection,
    opening: &mapi_proto::Execution,
    stream: ObjectHandle,
    first: &[u8],
    chunks: core::slice::Chunks<'_, u8>,
) -> Result<()> {
    check_written(opening, first.len())?;
    for chunk in chunks {
        let mut batch = RopBatch::new();
        let slot = batch.bind(stream);
        batch.write_stream(slot, chunk);
        let execution = connection
            .execute(batch, "writing an attachment's content")
            .await?;
        check_written(&execution, chunk.len())?;
    }
    Ok(())
}

/// Commits the content and gives both handles back — or, when the content did not all arrive,
/// gives them back and commits nothing.
///
/// **The release runs either way**, which is the same rule
/// [`StreamRead::read`](crate::StreamRead::read) follows on the way out of a failed read and for
/// the same reason: `check_written` refusing a short write is not a transport failure, so a caller
/// attaching a hundred files would leave two hundred handles behind on a connection that is still
/// perfectly usable.
///
/// The order on the success path is the one that does not lose the attachment — commit, release the
/// stream, save the attachment, release it — and is what the captured corpus holds.
async fn finish(
    connection: &mut Connection,
    stream: ObjectHandle,
    attachment: ObjectHandle,
    commit: bool,
) -> Result<()> {
    let mut batch = RopBatch::new();
    let stream = batch.bind(stream);
    let attachment = batch.bind(attachment);
    if commit {
        batch.commit_stream(stream);
    }
    batch.release(stream);
    if commit {
        batch.save_attachment(attachment);
    }
    batch.release(attachment);

    connection.execute(batch, "saving an attachment").await?;
    Ok(())
}

/// Refuses a write the server only partly accepted.
///
/// A short write **succeeds** as a ROP, so without this an attachment that arrived truncated would
/// be reported as saved — the write-side twin of a stream read that stops at the first short
/// answer.
fn check_written(execution: &mapi_proto::Execution, sent: usize) -> Result<()> {
    let written = execution
        .responses()
        .iter()
        .find_map(RopResponse::as_written)
        .map_or(0, |response| usize::from(response.written()));

    if written == sent {
        return Ok(());
    }
    Err(Error::Unexpected {
        expected: "the server to write every byte it was sent",
        found: "a short write, which succeeds as a ROP and leaves the value truncated",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attachment_takes_its_names_and_its_extension_from_one_file_name() {
        let attachment = NewAttachment::by_value("notes.txt", *b"one line\n").expect("a name");
        let tags: Vec<PropertyTag> = attachment.properties.iter().map(TaggedValue::tag).collect();

        assert!(tags.contains(&PropertyTag::ATTACH_METHOD));
        assert!(tags.contains(&PropertyTag::ATTACH_LONG_FILENAME));
        assert!(tags.contains(&PropertyTag::ATTACH_FILENAME));
        assert!(tags.contains(&PropertyTag::ATTACH_EXTENSION));
        assert!(tags.contains(&PropertyTag::DISPLAY_NAME));

        let extension = attachment
            .properties
            .iter()
            .find(|value| value.tag() == PropertyTag::ATTACH_EXTENSION)
            .map(TaggedValue::value);
        assert_eq!(
            extension
                .and_then(PropertyValue::as_string)
                .map(mapi_proto::TableString::as_str),
            Some(".txt")
        );
        assert_eq!(attachment.content(), b"one line\n");
    }

    /// A name with no dot has no extension, and inventing one would tell the receiving client
    /// something nobody said.
    #[test]
    fn a_file_name_with_no_extension_gets_an_empty_one() {
        let attachment = NewAttachment::by_value("README", Vec::new()).expect("a name");
        let extension = attachment
            .properties
            .iter()
            .find(|value| value.tag() == PropertyTag::ATTACH_EXTENSION)
            .and_then(|value| value.value().as_string())
            .map(mapi_proto::TableString::as_str);
        assert_eq!(extension, Some(""));
        assert!(attachment.content().is_empty());
    }

    /// A MIME type is not one of the five properties a file name produces, and an attachment that
    /// carries one is what stops the receiving client guessing at the bytes.
    #[test]
    fn an_attachment_carries_whatever_else_it_was_given() {
        let mime = TaggedValue::new(
            PropertyTag::ATTACH_MIME_TAG,
            PropertyValue::String("text/plain".into()),
        )
        .expect("a MIME type");

        let attachment = NewAttachment::by_value("notes.txt", *b"one line\n")
            .expect("a name")
            .set([mime.clone()]);

        assert_eq!(attachment.properties.len(), 6);
        assert_eq!(attachment.properties.last(), Some(&mime));
    }

    /// The chunk has to stay under the two-byte `DataSize` field and leave room for the rest of the
    /// ROP list, which `RopSize` bounds by the same width.
    #[test]
    fn the_write_chunk_stays_under_both_two_byte_limits() {
        const { assert!(WRITE_CHUNK <= 0xFFFF, "DataSize is two bytes") }
        const {
            assert!(
                WRITE_CHUNK <= 0xFFFF / 2,
                "RopSize counts every ROP in the buffer, and the write shares it"
            );
        }
    }
}
