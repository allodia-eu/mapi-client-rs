//! How many bytes a batch comes to, before it is built.

use super::*;

/// `size` is what the built buffer's `Size` field will say, so a caller can tell in advance
/// whether more fits — and building one byte past [`RopBatch::MAX_SIZE`] fails as it predicts.
#[test]
fn the_size_is_what_the_frame_will_carry() {
    let mut batch = RopBatch::new();
    let stream = batch.bind(ObjectHandle::new(0x2A));
    batch.write_stream(stream, &[0; 100]);
    let predicted = batch.size();
    let built = batch.build().unwrap();
    let framed = usize::from(u16::from_le_bytes([built.bytes[4], built.bytes[5]]));
    assert_eq!(predicted, framed);
    assert_eq!(predicted, built.bytes.len() - 8);

    let mut full = RopBatch::new();
    let stream = full.bind(ObjectHandle::new(0x2A));
    full.write_stream(stream, &[]);
    let room = RopBatch::MAX_SIZE - full.size();
    let mut exact = RopBatch::new();
    let stream = exact.bind(ObjectHandle::new(0x2A));
    exact.write_stream(stream, &vec![0; room]);
    assert_eq!(exact.size(), RopBatch::MAX_SIZE);
    assert!(exact.build().is_ok());

    let mut over = RopBatch::new();
    let stream = over.bind(ObjectHandle::new(0x2A));
    over.write_stream(stream, &vec![0; room + 1]);
    assert!(matches!(over.build(), Err(Error::RopBufferTooLarge { .. })));
}
