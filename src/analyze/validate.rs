use super::model::{CandidateProbeResult, DecryptCandidate, MAX_FFPROBE_CANDIDATES};
use anyhow::{Context, Result};
use std::{
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub(crate) trait CandidateValidator {
    fn validate(
        &self,
        decrypt_candidates: &[DecryptCandidate],
        report_path: &Path,
    ) -> Result<Vec<CandidateProbeResult>>;
}

pub(crate) struct FfprobeValidator;

impl CandidateValidator for FfprobeValidator {
    fn validate(
        &self,
        decrypt_candidates: &[DecryptCandidate],
        report_path: &Path,
    ) -> Result<Vec<CandidateProbeResult>> {
        let Some(ffprobe_bin) = locate_ffprobe() else {
            fs::write(
                report_path,
                "ffprobe not found in PATH or common locations; validation skipped.\n",
            )
            .with_context(|| format!("Failed to write {}", report_path.display()))?;
            return Ok(Vec::new());
        };

        let mut selected = decrypt_candidates
            .iter()
            .filter(|candidate| candidate.source_candidate.starts_with("structural_"))
            .take(MAX_FFPROBE_CANDIDATES)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            selected = decrypt_candidates
                .iter()
                .take(MAX_FFPROBE_CANDIDATES)
                .collect::<Vec<_>>();
        }

        let mut results = Vec::new();
        let mut report = String::new();
        let _ = writeln!(report, "ffprobe_bin={}", ffprobe_bin.display());

        for candidate in selected {
            let output = Command::new(&ffprobe_bin)
                .arg("-v")
                .arg("error")
                .arg("-show_entries")
                .arg("stream=codec_name,codec_type")
                .arg("-show_entries")
                .arg("format=format_name")
                .arg("-of")
                .arg("default=noprint_wrappers=1:nokey=0")
                .arg(&candidate.path)
                .output()
                .with_context(|| {
                    format!(
                        "Failed to run {} on {}",
                        ffprobe_bin.display(),
                        candidate.path.display()
                    )
                })?;

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let success = stdout.lines().any(|line| line == "codec_name=hevc")
                && stdout.lines().any(|line| line == "codec_type=video");

            let result = CandidateProbeResult {
                candidate_name: candidate.name.clone(),
                path: candidate.path.clone(),
                success,
                stdout,
                stderr,
            };
            let _ = writeln!(
                report,
                "candidate={} success={} path={}",
                result.candidate_name,
                result.success,
                result.path.display()
            );
            if !result.stdout.is_empty() {
                let _ = writeln!(report, "stdout={}", result.stdout.replace('\n', " | "));
            }
            if !result.stderr.is_empty() {
                let _ = writeln!(report, "stderr={}", result.stderr.replace('\n', " | "));
            }
            let _ = writeln!(report);
            results.push(result);
        }

        fs::write(report_path, report)
            .with_context(|| format!("Failed to write {}", report_path.display()))?;
        Ok(results)
    }
}

fn locate_ffprobe() -> Option<PathBuf> {
    let candidates = [
        "ffprobe",
        "/opt/homebrew/bin/ffprobe",
        "/usr/local/bin/ffprobe",
    ];

    candidates.iter().find_map(|candidate| {
        let path = PathBuf::from(candidate);
        if path.is_absolute() && path.exists() {
            Some(path)
        } else {
            Command::new("which")
                .arg(candidate)
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let found = stdout.trim();
                    if found.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(found))
                    }
                })
        }
    })
}
