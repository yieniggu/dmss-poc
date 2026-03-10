use super::model::{MediaChunkEntry, ANNEXB3, ANNEXB4};

pub(crate) fn find_subsequence(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|window| window == needle)
}

pub(crate) fn find_first_annexb(data: &[u8]) -> Option<usize> {
    let four = find_subsequence(data, ANNEXB4);
    let three = find_subsequence(data, ANNEXB3);
    match (four, three) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

pub(crate) fn find_first_annexb_with_len(data: &[u8]) -> Option<(usize, usize)> {
    let four = find_subsequence(data, ANNEXB4).map(|offset| (offset, 4));
    let three = find_subsequence(data, ANNEXB3).map(|offset| (offset, 3));
    match (four, three) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

pub(crate) fn concat_non_http_chunks(media_blob: &[u8], chunks: &[MediaChunkEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks.iter().filter(|chunk| !chunk.starts_with_http) {
        out.extend_from_slice(&media_blob[chunk.offset..chunk.offset + chunk.len]);
    }
    out
}

pub(crate) fn concat_chunks(media_blob: &[u8], chunks: &[&MediaChunkEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend_from_slice(&media_blob[chunk.offset..chunk.offset + chunk.len]);
    }
    out
}

pub(crate) fn most_common_len(chunks: &[&MediaChunkEntry]) -> Option<usize> {
    let mut counts = std::collections::BTreeMap::<usize, usize>::new();
    for chunk in chunks {
        *counts.entry(chunk.len).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
        .map(|(len, _)| len)
}

pub(crate) fn ratio_per_mille(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    ((numerator as u64 * 1000) / denominator as u64) as u32
}

pub(crate) fn preview_hex(data: &[u8], max_len: usize) -> String {
    data.iter()
        .take(max_len)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
