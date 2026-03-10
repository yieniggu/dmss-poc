use super::{
    decrypt::{first_hevc_header, sample_hevc_headers},
    experiments::{xor_after_first_annexb, xor_after_first_annexb_by_lane},
    model::{
        ExtractionCandidate, OracleCandidate, ReferenceBlobSummary, MAX_HEVC_HEADERS_TO_SCORE,
    },
    util::{find_first_annexb, preview_hex, ratio_per_mille},
};
use anyhow::{Context, Result};
use std::{fs, path::Path};

pub(crate) fn summarize_reference_blob(name: &str, path: &Path) -> Result<ReferenceBlobSummary> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(summarize_reference_bytes(name, path, &bytes))
}

pub(crate) fn summarize_reference_bytes(
    name: &str,
    path: &Path,
    bytes: &[u8],
) -> ReferenceBlobSummary {
    ReferenceBlobSummary {
        name: name.to_string(),
        path: path.to_path_buf(),
        bytes: bytes.len(),
        first_dhav_offset: find_subsequence(bytes, b"DHAV"),
        first_annexb_offset: find_first_annexb(bytes),
        header_sample: sample_hevc_headers(bytes, MAX_HEVC_HEADERS_TO_SCORE),
        preview_hex: preview_hex(bytes, 32),
    }
}

pub(crate) fn extract_reference_annexb_blob(
    output_dir: &Path,
    reference: &ReferenceBlobSummary,
) -> Result<ReferenceBlobSummary> {
    let bytes = fs::read(&reference.path)
        .with_context(|| format!("Failed to read {}", reference.path.display()))?;
    let Some(offset) = find_first_annexb(&bytes) else {
        return Ok(summarize_reference_bytes(
            &format!("{}_annexb", reference.name),
            &reference.path,
            &bytes,
        ));
    };
    let extracted = &bytes[offset..];
    let path = output_dir.join(format!("{}_annexb.bin", reference.name));
    fs::write(&path, extracted).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(summarize_reference_bytes(
        &format!("{}_annexb", reference.name),
        &path,
        extracted,
    ))
}

pub(crate) fn build_oracle_candidates(
    output_dir: &Path,
    extraction_candidates: &[ExtractionCandidate],
    reference_h264: &ReferenceBlobSummary,
    reference_raw_annexb: &ReferenceBlobSummary,
) -> Result<Vec<OracleCandidate>> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let mut out = Vec::new();
    let references = [reference_h264, reference_raw_annexb];
    let sources = extraction_candidates.iter().take(12).collect::<Vec<_>>();

    for source in sources {
        let source_bytes = fs::read(&source.path)
            .with_context(|| format!("Failed to read {}", source.path.display()))?;
        for reference in references {
            let reference_bytes = fs::read(&reference.path)
                .with_context(|| format!("Failed to read {}", reference.path.display()))?;

            if let Some((key, ratio)) = infer_constant_xor(&source_bytes, &reference_bytes) {
                let bytes = xor_after_first_annexb(&source_bytes, key);
                push_oracle_candidate(
                    &mut out,
                    output_dir,
                    source,
                    reference,
                    &format!("constant_xor_{key:02x}"),
                    &bytes,
                    ratio,
                )?;
            }

            for lane in infer_lane_xor(&source_bytes, &reference_bytes, 2)
                .into_iter()
                .chain(infer_lane_xor(&source_bytes, &reference_bytes, 4).into_iter())
                .take(8)
            {
                let bytes = xor_after_first_annexb_by_lane(
                    &source_bytes,
                    lane.period,
                    lane.lane,
                    lane.xor_key,
                );
                push_oracle_candidate(
                    &mut out,
                    output_dir,
                    source,
                    reference,
                    &format!(
                        "lane_xor_p{}_l{}_{}",
                        lane.period, lane.lane, format!("{:02x}", lane.xor_key)
                    ),
                    &bytes,
                    lane.match_ratio_per_mille,
                )?;
            }
        }
    }

    out.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.match_ratio_per_mille.cmp(&a.match_ratio_per_mille))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(out)
}

fn push_oracle_candidate(
    out: &mut Vec<OracleCandidate>,
    output_dir: &Path,
    source: &ExtractionCandidate,
    reference: &ReferenceBlobSummary,
    method: &str,
    bytes: &[u8],
    match_ratio_per_mille: u32,
) -> Result<()> {
    let name = format!("{}_{}_{}", source.name, reference.name, method);
    let path = output_dir.join(format!("{}.bin", name));
    fs::write(&path, bytes).with_context(|| format!("Failed to write {}", path.display()))?;
    let header_sample = sample_hevc_headers(bytes, MAX_HEVC_HEADERS_TO_SCORE);
    let hevc = header_sample.first().cloned();
    let score = (header_sample.len() as u32 * 10)
        + if hevc.is_some() { 20 } else { 0 }
        + (match_ratio_per_mille / 10);

    out.push(OracleCandidate {
        name,
        source_candidate: source.name.clone(),
        reference_name: reference.name.clone(),
        path,
        bytes: bytes.len(),
        score,
        method: method.to_string(),
        preview_hex: preview_hex(bytes, 32),
        match_ratio_per_mille,
        hevc,
    });
    Ok(())
}

fn infer_constant_xor(cipher: &[u8], plain: &[u8]) -> Option<(u8, u32)> {
    let cipher_start = first_hevc_header(cipher)?.nal_header_offset;
    let plain_start = first_hevc_header(plain)?.nal_header_offset;
    let limit = cipher.len().min(plain.len()).min(cipher_start + 4096);
    if limit <= cipher_start || limit <= plain_start {
        return None;
    }

    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for idx in 0..(limit - cipher_start).min(limit - plain_start) {
        let key = cipher[cipher_start + idx] ^ plain[plain_start + idx];
        counts[key as usize] += 1;
        total += 1;
    }
    let (best_key, best_count) = counts.iter().enumerate().max_by_key(|(_, c)| *c)?;
    Some((best_key as u8, ratio_per_mille(*best_count, total)))
}

struct LaneInsight {
    period: usize,
    lane: usize,
    xor_key: u8,
    match_ratio_per_mille: u32,
}

fn infer_lane_xor(cipher: &[u8], plain: &[u8], period: usize) -> Vec<LaneInsight> {
    let Some(cipher_start) = first_hevc_header(cipher).map(|h| h.nal_header_offset) else {
        return Vec::new();
    };
    let Some(plain_start) = first_hevc_header(plain).map(|h| h.nal_header_offset) else {
        return Vec::new();
    };
    let limit = cipher.len().min(plain.len()).min(cipher_start + 4096);
    if limit <= cipher_start || limit <= plain_start {
        return Vec::new();
    }

    let span = (limit - cipher_start).min(limit - plain_start);
    let mut out = Vec::new();
    for lane in 0..period {
        let mut counts = [0usize; 256];
        let mut total = 0usize;
        for idx in 0..span {
            if idx % period != lane {
                continue;
            }
            let key = cipher[cipher_start + idx] ^ plain[plain_start + idx];
            counts[key as usize] += 1;
            total += 1;
        }
        if total == 0 {
            continue;
        }
        let (best_key, best_count) = match counts.iter().enumerate().max_by_key(|(_, c)| *c) {
            Some(value) => value,
            None => continue,
        };
        out.push(LaneInsight {
            period,
            lane,
            xor_key: best_key as u8,
            match_ratio_per_mille: ratio_per_mille(*best_count, total),
        });
    }

    out.sort_by(|a, b| {
        b.match_ratio_per_mille
            .cmp(&a.match_ratio_per_mille)
            .then_with(|| a.period.cmp(&b.period))
            .then_with(|| a.lane.cmp(&b.lane))
    });
    out
}


fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}
