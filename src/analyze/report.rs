use super::model::{
    CaptureAnalysis, CandidateProbeResult, OracleCandidate, ReferenceBlobSummary, ReferenceComparison,
};
use std::fmt::Write;

pub fn render_analysis_report(analysis: &CaptureAnalysis) -> String {
    let core = &analysis.core;
    let mut out = String::new();
    let _ = writeln!(out, "capture_dir={}", core.capture_dir.display());
    let _ = writeln!(out, "total_media_bytes={}", core.total_media_bytes);
    let _ = writeln!(out, "track_count={}", core.sdp.tracks.len());
    let _ = writeln!(out, "encrypt_alg={:?}", core.sdp.encrypt_alg);
    let _ = writeln!(out, "first_dhav_offset={:?}", core.first_dhav_offset);
    let _ = writeln!(out, "first_annexb_offset={:?}", core.first_annexb_offset);
    let _ = writeln!(out, "analysis_artifacts_dir={}", core.analysis_artifacts_dir.display());
    let _ = writeln!(out, "decrypt_candidates_dir={}", core.decrypt_candidates_dir.display());
    let _ = writeln!(out, "ffprobe_validation_path={}", analysis.ffprobe_validation_path.display());
    let _ = writeln!(out, "candidate_h265_path={:?}", analysis.candidate_h265_path);
    let _ = writeln!(out);

    let _ = writeln!(out, "[tracks]");
    for (idx, track) in core.sdp.tracks.iter().enumerate() {
        let _ = writeln!(
            out,
            "track#{} media={} control={:?} rtpmap={:?} framerate={:?} recvonly={}",
            idx, track.media, track.control, track.rtpmap, track.framerate, track.recvonly
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "[chunks]");
    for chunk in &core.chunks {
        let _ = writeln!(
            out,
            "chunk#{} offset={} len={} starts_with_http={} dhav_offset={:?} annexb_offset={:?}",
            chunk.index,
            chunk.offset,
            chunk.len,
            chunk.starts_with_http,
            chunk.dhav_offset,
            chunk.annexb_offset
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "[media_structure]");
    let _ = writeln!(out, "structural_dir={}", core.media_structure.structural_dir.display());
    if let Some(continuation) = &core.media_structure.continuation {
        let _ = writeln!(
            out,
            "continuation first_index={} count={} common_len={:?} total_bytes={}",
            continuation.first_index,
            continuation.count,
            continuation.common_len,
            continuation.total_bytes
        );
    } else {
        let _ = writeln!(out, "continuation=None");
    }
    let _ = writeln!(out, "annexb_tail_len={:?}", core.media_structure.annexb_tail_len);
    for region in &core.media_structure.regions {
        let _ = writeln!(
            out,
            "region {} offset={} len={} path={:?} notes={:?}",
            region.name, region.offset, region.len, region.path, region.notes
        );
    }
    for note in &core.media_structure.notes {
        let _ = writeln!(out, "note={}", note);
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "[playback_blockers]");
    for blocker in &analysis.playback_blockers {
        let _ = writeln!(out, "blocker={}", blocker);
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "[extraction_candidates]");
    for candidate in core.extraction_candidates.iter().take(16) {
        let _ = writeln!(
            out,
            "{} bytes={} first_dhav_offset={:?} first_annexb_offset={:?} path={}",
            candidate.name,
            candidate.bytes,
            candidate.first_dhav_offset,
            candidate.first_annexb_offset,
            candidate.path.display()
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "[ffprobe_results]");
    for result in analysis.ffprobe_results.iter().take(16) {
        render_probe_result(&mut out, result);
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "[decrypt_candidates]");
    for candidate in core.decrypt_candidates.iter().take(24) {
        let hevc = candidate.hevc.as_ref().map(|info| {
            format!(
                "nal_type={} temporal_id_plus1={} start_code_offset={} start_code_len={}",
                info.nal_unit_type,
                info.temporal_id_plus1,
                info.start_code_offset,
                info.start_code_len
            )
        });
        let _ = writeln!(
            out,
            "{} source={} transform={} xor_key={:?} score={} continuity_bonus={} bytes={} hevc={:?} path={}",
            candidate.name,
            candidate.source_candidate,
            candidate.transform,
            candidate.xor_key,
            candidate.score,
            candidate.continuity_bonus,
            candidate.bytes,
            hevc,
            candidate.path.display()
        );
    }

    out
}

pub fn render_reference_comparison_report(comparison: &ReferenceComparison) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "capture_dir={}", comparison.analysis.core.capture_dir.display());
    let _ = writeln!(out, "oracle_candidates_dir={}", comparison.oracle_candidates_dir.display());
    let _ = writeln!(out, "report_path={}", comparison.report_path.display());
    let _ = writeln!(out);

    let _ = writeln!(out, "[reference_h264]");
    render_reference_blob(&mut out, &comparison.reference_h264);
    let _ = writeln!(out, "[reference_private]");
    render_reference_blob(&mut out, &comparison.reference_private);
    let _ = writeln!(out, "[reference_raw_annexb]");
    render_reference_blob(&mut out, &comparison.reference_raw_annexb);
    let _ = writeln!(out);

    let _ = writeln!(out, "[oracle_candidates]");
    for candidate in comparison.oracle_candidates.iter().take(24) {
        render_oracle_candidate(&mut out, candidate);
    }

    out
}

fn render_reference_blob(out: &mut String, blob: &ReferenceBlobSummary) {
    let _ = writeln!(out, "name={}", blob.name);
    let _ = writeln!(out, "path={}", blob.path.display());
    let _ = writeln!(out, "bytes={}", blob.bytes);
    let _ = writeln!(out, "first_dhav_offset={:?}", blob.first_dhav_offset);
    let _ = writeln!(out, "first_annexb_offset={:?}", blob.first_annexb_offset);
    let _ = writeln!(out, "preview_hex={}", blob.preview_hex);
    for (idx, header) in blob.header_sample.iter().take(6).enumerate() {
        let _ = writeln!(
            out,
            "header#{} nal_type={} temporal_id_plus1={} start_code_offset={} start_code_len={}",
            idx,
            header.nal_unit_type,
            header.temporal_id_plus1,
            header.start_code_offset,
            header.start_code_len
        );
    }
}

fn render_oracle_candidate(out: &mut String, candidate: &OracleCandidate) {
    let hevc = candidate.hevc.as_ref().map(|info| {
        format!(
            "nal_type={} temporal_id_plus1={} start_code_offset={} start_code_len={}",
            info.nal_unit_type,
            info.temporal_id_plus1,
            info.start_code_offset,
            info.start_code_len
        )
    });
    let _ = writeln!(
        out,
        "{} source={} reference={} method={} match_ratio_per_mille={} score={} hevc={:?} path={}",
        candidate.name,
        candidate.source_candidate,
        candidate.reference_name,
        candidate.method,
        candidate.match_ratio_per_mille,
        candidate.score,
        hevc,
        candidate.path.display()
    );
}

fn render_probe_result(out: &mut String, result: &CandidateProbeResult) {
    let _ = writeln!(
        out,
        "candidate={} success={} path={}",
        result.candidate_name,
        result.success,
        result.path.display()
    );
    if !result.stdout.is_empty() {
        let _ = writeln!(out, "stdout={}", result.stdout.replace('\n', " | "));
    }
    if !result.stderr.is_empty() {
        let _ = writeln!(out, "stderr={}", result.stderr.replace('\n', " | "));
    }
}
