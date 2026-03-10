use super::{
    model::{CaptureAnalysis, ReferenceComparison},
    reference::{build_oracle_candidates, extract_reference_annexb_blob, summarize_reference_blob},
    report::render_reference_comparison_report,
};
use anyhow::{Context, Result};
use std::{fs, path::Path};

pub(crate) fn compare_with_references(
    analysis: CaptureAnalysis,
    capture_dir: &Path,
    reference_h264: &Path,
    reference_private: &Path,
) -> Result<ReferenceComparison> {
    let oracle_candidates_dir = capture_dir.join("analysis_artifacts").join("reference_oracle");
    fs::create_dir_all(&oracle_candidates_dir)
        .with_context(|| format!("Failed to create {}", oracle_candidates_dir.display()))?;

    let reference_h264 = summarize_reference_blob("reference_h264", reference_h264)?;
    let reference_private = summarize_reference_blob("reference_private", reference_private)?;
    let reference_raw_annexb =
        extract_reference_annexb_blob(&oracle_candidates_dir, &reference_private)?;
    let oracle_candidates = build_oracle_candidates(
        &oracle_candidates_dir,
        &analysis.core.extraction_candidates,
        &reference_h264,
        &reference_raw_annexb,
    )?;

    let report_path = capture_dir.join("analysis_artifacts").join("reference_comparison.txt");
    let comparison = ReferenceComparison {
        analysis,
        reference_h264,
        reference_private,
        reference_raw_annexb,
        oracle_candidates_dir,
        oracle_candidates,
        report_path,
    };

    let report = render_reference_comparison_report(&comparison);
    fs::write(&comparison.report_path, report)
        .with_context(|| format!("Failed to write {}", comparison.report_path.display()))?;
    Ok(comparison)
}
