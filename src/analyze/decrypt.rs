use super::{
    experiment::{ranked_limit, InclusionMode},
    experiments::registered_experiments,
    model::{
        DecryptCandidate, HevcHeaderInfo, MediaStructureAnalysis, StructuredDataset,
        StructuredDatasetKind, MAX_HEVC_HEADERS_TO_SCORE,
    },
    util::{find_first_annexb_with_len, preview_hex},
};
use anyhow::{Context, Result};
use std::{fs, path::Path};

pub(crate) fn build_decrypt_candidates(
    output_dir: &Path,
    datasets: &[StructuredDataset],
    media_structure: &MediaStructureAnalysis,
) -> Result<Vec<DecryptCandidate>> {
    let mut out = Vec::new();
    let experiments = registered_experiments();

    for dataset in datasets {
        let bytes = fs::read(&dataset.path)
            .with_context(|| format!("Failed to read {}", dataset.path.display()))?;

        for experiment in &experiments {
            let outputs = experiment.generate(dataset, &bytes, media_structure);
            match experiment.inclusion_mode() {
                InclusionMode::AlwaysInclude => {
                    for output in outputs {
                        push_candidate_file(
                            &mut out,
                            output_dir,
                            &output.suffix,
                            dataset,
                            &output.bytes,
                            output.xor_key,
                            &output.transform,
                            media_structure,
                        )?;
                    }
                }
                InclusionMode::Ranked => {
                    let mut ranked = outputs
                        .into_iter()
                        .map(|output| {
                            let headers = sample_hevc_headers(&output.bytes, MAX_HEVC_HEADERS_TO_SCORE);
                            let score = candidate_score(dataset, &headers, media_structure);
                            (score, output, headers)
                        })
                        .collect::<Vec<_>>();
                    ranked.sort_by(|a, b| {
                        b.0.cmp(&a.0)
                            .then_with(|| a.1.suffix.cmp(&b.1.suffix))
                    });
                    for (_score, output, _) in ranked.into_iter().take(ranked_limit()) {
                        push_candidate_file(
                            &mut out,
                            output_dir,
                            &format!("{}_{}", dataset.name, output.suffix),
                            dataset,
                            &output.bytes,
                            output.xor_key,
                            &output.transform,
                            media_structure,
                        )?;
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(out)
}

pub(crate) fn push_candidate_file(
    candidates: &mut Vec<DecryptCandidate>,
    output_dir: &Path,
    name: &str,
    source: &StructuredDataset,
    bytes: &[u8],
    xor_key: Option<u8>,
    transform: &str,
    media_structure: &MediaStructureAnalysis,
) -> Result<()> {
    let path = output_dir.join(format!("{name}.bin"));
    fs::write(&path, bytes).with_context(|| format!("Failed to write {}", path.display()))?;
    let header_sample = sample_hevc_headers(bytes, MAX_HEVC_HEADERS_TO_SCORE);
    let hevc = header_sample.first().cloned();
    let continuity = continuity_bonus(source, &header_sample, media_structure);
    let sequence = hevc_sequence_bonus(&header_sample);
    let score = candidate_score(source, &header_sample, media_structure).max(0) as u32;
    candidates.push(DecryptCandidate {
        name: name.to_string(),
        source_candidate: source.source_candidate.clone(),
        source_kind: source.kind,
        path,
        bytes: bytes.len(),
        xor_key,
        transform: transform.to_string(),
        score,
        continuity_bonus: continuity + sequence,
        hevc,
        header_sample,
        preview_hex: preview_hex(bytes, 32),
    });
    Ok(())
}

pub(crate) fn first_hevc_header(data: &[u8]) -> Option<HevcHeaderInfo> {
    let (start_code_offset, start_code_len) = find_first_annexb_with_len(data)?;
    let nal_header_offset = start_code_offset + start_code_len;
    let nal_header = data.get(nal_header_offset..nal_header_offset + 2)?;
    let nal_unit_type = (nal_header[0] >> 1) & 0x3f;
    let temporal_id_plus1 = nal_header[1] & 0x07;
    Some(HevcHeaderInfo {
        start_code_offset,
        start_code_len,
        nal_header_offset,
        nal_unit_type,
        temporal_id_plus1,
    })
}

pub(crate) fn sample_hevc_headers(data: &[u8], max_headers: usize) -> Vec<HevcHeaderInfo> {
    let mut headers = Vec::new();
    let mut idx = 0usize;
    while idx < data.len() && headers.len() < max_headers {
        let Some((offset, len)) = find_first_annexb_with_len(&data[idx..]) else {
            break;
        };
        let start_code_offset = idx + offset;
        let nal_header_offset = start_code_offset + len;
        let Some(nal_header) = data.get(nal_header_offset..nal_header_offset + 2) else {
            break;
        };
        headers.push(HevcHeaderInfo {
            start_code_offset,
            start_code_len: len,
            nal_header_offset,
            nal_unit_type: (nal_header[0] >> 1) & 0x3f,
            temporal_id_plus1: nal_header[1] & 0x07,
        });
        idx = nal_header_offset + 2;
    }
    headers
}

pub(crate) fn candidate_score(
    source: &StructuredDataset,
    headers: &[HevcHeaderInfo],
    media_structure: &MediaStructureAnalysis,
) -> i32 {
    (hevc_score(headers) as i32
        + continuity_bonus(source, headers, media_structure)
        + hevc_sequence_bonus(headers))
        .max(0)
}

pub(crate) fn hevc_sequence_bonus(headers: &[HevcHeaderInfo]) -> i32 {
    if headers.is_empty() {
        return 0;
    }

    let mut bonus = 0;
    let nal_types = headers.iter().map(|header| header.nal_unit_type).collect::<Vec<_>>();

    if nal_types.windows(3).any(|window| window == [32, 33, 34]) {
        bonus += 30;
    }
    if nal_types.iter().take(4).any(|nal| (0..=31).contains(nal))
        && nal_types.iter().take(4).any(|nal| matches!(*nal, 32..=34))
    {
        bonus += 10;
    }
    if nal_types
        .windows(4)
        .any(|window| window[0] == 32 && window[1] == 33 && window[2] == 34 && (0..=31).contains(&window[3]))
    {
        bonus += 20;
    }
    bonus
}

fn continuity_bonus(
    source: &StructuredDataset,
    headers: &[HevcHeaderInfo],
    media_structure: &MediaStructureAnalysis,
) -> i32 {
    let mut bonus = 0;
    match source.kind {
        StructuredDatasetKind::AnnexBTail => bonus += 12,
        StructuredDatasetKind::AnnexBPlusContinuation => bonus += 20,
        StructuredDatasetKind::ContinuationChunks => bonus += 4,
        _ => {}
    }
    if media_structure.continuation.as_ref().is_some_and(|continuation| continuation.count > 0) && headers.len() >= 2 {
        bonus += 8;
    }
    if headers.iter().filter(|header| (0..=31).contains(&header.nal_unit_type)).count() >= 2 {
        bonus += 12;
    }
    bonus
}

fn hevc_score(headers: &[HevcHeaderInfo]) -> u32 {
    let Some(first) = headers.first() else {
        return 0;
    };

    let mut score = match first.nal_unit_type {
        32..=34 => 100,
        39 | 40 => 85,
        19..=21 => 75,
        16..=18 => 55,
        0..=31 => 25,
        32..=63 => 15,
        _ => 0,
    };

    if (1..=7).contains(&first.temporal_id_plus1) {
        score += 20;
    }
    if first.start_code_offset == 0 {
        score += 10;
    }

    let mut saw_vps = false;
    let mut saw_sps = false;
    let mut saw_pps = false;
    let mut plausible_headers = 0u32;
    for header in headers {
        if (1..=7).contains(&header.temporal_id_plus1) {
            plausible_headers += 1;
        }
        match header.nal_unit_type {
            32 => saw_vps = true,
            33 => saw_sps = true,
            34 => saw_pps = true,
            _ => {}
        }
    }

    score += plausible_headers.min(6) * 8;
    if saw_vps {
        score += 15;
    }
    if saw_sps {
        score += 15;
    }
    if saw_pps {
        score += 15;
    }
    if saw_vps && saw_sps && saw_pps {
        score += 40;
    }

    score
}
