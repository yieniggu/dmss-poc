mod core;
mod decrypt;
mod experiment;
mod experiments;
mod model;
mod planner;
mod reference;
mod reference_pipeline;
mod report;
mod structure;
#[cfg(test)]
mod tests;
mod util;
mod validate;

pub use report::{render_analysis_report, render_reference_comparison_report};

use anyhow::{Context, Result};
use model::{CaptureAnalysis, ReferenceComparison};
use std::{fs, path::Path};
use validate::{CandidateValidator, FfprobeValidator};

pub fn analyze_capture_dir(dir: &Path) -> Result<CaptureAnalysis> {
    let core = core::analyze_capture_core(dir)?;
    let analysis_artifacts_dir = core.analysis_artifacts_dir.clone();
    let ffprobe_validation_path = analysis_artifacts_dir.join("ffprobe_validation.txt");
    let report_path = core.capture_dir.join("analysis.txt");
    let ffprobe_results =
        FfprobeValidator.validate(&core.decrypt_candidates, &ffprobe_validation_path)?;

    let candidate_h265_path = ffprobe_results
        .iter()
        .find(|result| result.success)
        .map(|result| result.path.clone())
        .or_else(|| core.decrypt_candidates.first().map(|candidate| candidate.path.clone()));

    let playback_blockers =
        core::build_playback_blockers(&core.sdp, &ffprobe_results, &core.decrypt_candidates);

    let analysis = CaptureAnalysis {
        core,
        ffprobe_validation_path,
        ffprobe_results,
        report_path,
        candidate_h265_path,
        playback_blockers,
    };

    let report = report::render_analysis_report(&analysis);
    fs::write(&analysis.report_path, report)
        .with_context(|| format!("Failed to write {}", analysis.report_path.display()))?;
    Ok(analysis)
}

pub fn compare_capture_with_references(
    capture_dir: &Path,
    reference_h264: &Path,
    reference_private: &Path,
) -> Result<ReferenceComparison> {
    let analysis = analyze_capture_dir(capture_dir)?;
    reference_pipeline::compare_with_references(analysis, capture_dir, reference_h264, reference_private)
}
