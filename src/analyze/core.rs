use super::{
    decrypt,
    model::{CandidateProbeResult, CaptureCoreAnalysis, DecryptCandidate, ParsedSdp},
    planner,
    structure::{
        analyze_media_structure, build_extraction_candidates, parse_chunk_index, parse_private_sdp,
    },
    util::{find_first_annexb, find_subsequence},
};
use anyhow::{Context, Result};
use std::{fs, path::Path};

pub(crate) fn analyze_capture_core(dir: &Path) -> Result<CaptureCoreAnalysis> {
    let capture_dir = dir.to_path_buf();
    let headers_path = dir.join("play_response_headers.txt");
    let private_sdp_path = dir.join("private_sdp.bin");
    let media_chunks_path = dir.join("media_chunks.bin");
    let chunk_index_path = dir.join("media_chunk_index.txt");
    let analysis_artifacts_dir = dir.join("analysis_artifacts");
    let decrypt_candidates_dir = analysis_artifacts_dir.join("decrypt_candidates");

    fs::create_dir_all(&decrypt_candidates_dir)
        .with_context(|| format!("Failed to create {}", decrypt_candidates_dir.display()))?;

    let headers = fs::read_to_string(&headers_path)
        .with_context(|| format!("Failed to read {}", headers_path.display()))?;
    let private_sdp = fs::read(&private_sdp_path)
        .with_context(|| format!("Failed to read {}", private_sdp_path.display()))?;
    let media_blob = fs::read(&media_chunks_path)
        .with_context(|| format!("Failed to read {}", media_chunks_path.display()))?;
    let chunk_index = fs::read_to_string(&chunk_index_path)
        .with_context(|| format!("Failed to read {}", chunk_index_path.display()))?;

    let sdp = parse_private_sdp(&private_sdp)?;
    let chunks = parse_chunk_index(&chunk_index, &media_blob)?;
    let first_dhav_offset = find_subsequence(&media_blob, b"DHAV");
    let first_annexb_offset = find_first_annexb(&media_blob);
    let media_structure = analyze_media_structure(dir, &media_blob, &chunks)?;
    let extraction_candidates = build_extraction_candidates(
        &analysis_artifacts_dir,
        &media_blob,
        &chunks,
        &media_structure,
    )?;
    let structured_datasets =
        planner::build_structured_datasets(&extraction_candidates, &media_structure);
    let planned_datasets = planner::plan_decrypt_datasets(&structured_datasets);
    let decrypt_candidates = decrypt::build_decrypt_candidates(
        &decrypt_candidates_dir,
        &planned_datasets,
        &media_structure,
    )?;

    Ok(CaptureCoreAnalysis {
        capture_dir,
        headers,
        private_sdp_path,
        media_chunks_path,
        chunk_index_path,
        analysis_artifacts_dir,
        decrypt_candidates_dir,
        total_media_bytes: media_blob.len(),
        first_dhav_offset,
        first_annexb_offset,
        sdp,
        chunks,
        media_structure,
        extraction_candidates,
        structured_datasets,
        decrypt_candidates,
    })
}

pub(crate) fn build_playback_blockers(
    sdp: &ParsedSdp,
    ffprobe_results: &[CandidateProbeResult],
    decrypt_candidates: &[DecryptCandidate],
) -> Vec<String> {
    let mut blockers = Vec::new();

    if matches!(sdp.encrypt_alg.as_deref(), Some("encrypt2")) {
        blockers
            .push("media still uses encrypt2; clean H.265 extraction is not solved yet".to_string());
    }
    if !ffprobe_results.iter().any(|result| result.success) {
        blockers.push("no decrypt candidate validated as HEVC via ffprobe".to_string());
    }
    if decrypt_candidates.is_empty() {
        blockers.push("no decrypt candidates were generated".to_string());
    }

    blockers
}
