use anyhow::{bail, Context, Result};
use std::{collections::HashSet, fs, path::Path};

use super::{
    model::{
        ContinuationChunkStats, ExtractionCandidate, MediaChunkEntry, MediaStructureAnalysis,
        ParsedSdp, SdpTrack, StructuralRegion, DHAV_MAGIC, HEADER_SKIP_CANDIDATES,
    },
    util::{concat_chunks, concat_non_http_chunks, find_first_annexb, find_first_annexb_with_len, find_subsequence, most_common_len, preview_hex},
};

pub(crate) fn parse_private_sdp(data: &[u8]) -> Result<ParsedSdp> {
    let text = std::str::from_utf8(data).context("private_sdp.bin is not valid UTF-8")?;
    let mut encrypt_alg = None;
    let mut tracks = Vec::new();
    let mut current: Option<SdpTrack> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("a=encryptalg:") {
            encrypt_alg = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("m=") {
            if let Some(track) = current.take() {
                tracks.push(track);
            }
            current = Some(SdpTrack {
                media: rest.trim().to_string(),
                control: None,
                rtpmap: None,
                framerate: None,
                recvonly: false,
            });
            continue;
        }

        let Some(track) = current.as_mut() else {
            continue;
        };

        if let Some(rest) = line.strip_prefix("a=control:") {
            track.control = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            track.rtpmap = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=framerate:") {
            track.framerate = Some(rest.trim().to_string());
        } else if line == "a=recvonly" {
            track.recvonly = true;
        }
    }

    if let Some(track) = current.take() {
        tracks.push(track);
    }

    if tracks.is_empty() {
        bail!("private_sdp.bin did not contain any SDP tracks");
    }

    Ok(ParsedSdp { encrypt_alg, tracks })
}

pub(crate) fn parse_chunk_index(index_text: &str, media_blob: &[u8]) -> Result<Vec<MediaChunkEntry>> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;

    for (line_no, raw_line) in index_text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let index = parts
            .next()
            .context("chunk index entry missing index")?
            .parse::<usize>()
            .with_context(|| format!("invalid chunk index at line {}", line_no + 1))?;
        let len = parts
            .next()
            .context("chunk index entry missing length")?
            .parse::<usize>()
            .with_context(|| format!("invalid chunk length at line {}", line_no + 1))?;
        if parts.next().is_some() {
            bail!("unexpected extra fields in chunk index line {}", line_no + 1);
        }
        if offset + len > media_blob.len() {
            bail!(
                "chunk {} exceeds media blob bounds (offset={} len={} blob={})",
                index,
                offset,
                len,
                media_blob.len()
            );
        }

        let chunk = &media_blob[offset..offset + len];
        let starts_with_http = chunk.starts_with(b"HTTP/");
        let dhav_offset = find_subsequence(chunk, DHAV_MAGIC);
        let annexb_offset = find_first_annexb(chunk);
        chunks.push(MediaChunkEntry {
            index,
            offset,
            len,
            starts_with_http,
            dhav_offset,
            annexb_offset,
        });
        offset += len;
    }

    if offset != media_blob.len() {
        bail!(
            "chunk index length mismatch: indexed {} bytes but media blob has {} bytes",
            offset,
            media_blob.len()
        );
    }

    if chunks.is_empty() {
        bail!("media_chunk_index.txt did not contain any chunks");
    }

    Ok(chunks)
}

pub(crate) fn analyze_media_structure(
    capture_dir: &Path,
    media_blob: &[u8],
    chunks: &[MediaChunkEntry],
) -> Result<MediaStructureAnalysis> {
    let structural_dir = capture_dir.join("analysis_artifacts").join("structural");
    fs::create_dir_all(&structural_dir)
        .with_context(|| format!("creating {}", structural_dir.display()))?;

    let mut regions = Vec::new();
    let mut notes = Vec::new();

    let non_http_chunks: Vec<&MediaChunkEntry> = chunks.iter().filter(|chunk| !chunk.starts_with_http).collect();
    if non_http_chunks.is_empty() {
        notes.push("No non-HTTP media chunks were captured".to_string());
        return Ok(MediaStructureAnalysis {
            structural_dir,
            regions,
            continuation: None,
            annexb_tail_len: None,
            notes,
        });
    }

    let first_media_chunk = non_http_chunks[0];
    notes.push(format!(
        "First media chunk is chunk#{} (offset={} len={})",
        first_media_chunk.index, first_media_chunk.offset, first_media_chunk.len
    ));

    let continuation_chunks: Vec<&MediaChunkEntry> = non_http_chunks.iter().skip(1).copied().collect();
    let continuation = if continuation_chunks.is_empty() {
        None
    } else {
        let bytes = concat_chunks(media_blob, &continuation_chunks);
        let path = structural_dir.join("continuation_chunks.bin");
        fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        regions.push(StructuralRegion {
            name: "continuation_chunks".to_string(),
            offset: continuation_chunks[0].offset,
            len: bytes.len(),
            path: Some(path),
            notes: format!(
                "Concatenation of {} continuation chunks after the first media chunk",
                continuation_chunks.len()
            ),
        });
        Some(ContinuationChunkStats {
            first_index: continuation_chunks[0].index,
            count: continuation_chunks.len(),
            common_len: most_common_len(&continuation_chunks),
            total_bytes: bytes.len(),
        })
    };

    let first_bytes = &media_blob[first_media_chunk.offset..first_media_chunk.offset + first_media_chunk.len];
    let mut annexb_tail_len = None;

    if let Some((annexb_offset, _start_code_len)) = find_first_annexb_with_len(first_bytes) {
        let prefix = &first_bytes[..annexb_offset];
        let prefix_path = structural_dir.join("chunk_prefix_before_annexb.bin");
        fs::write(&prefix_path, prefix).with_context(|| format!("writing {}", prefix_path.display()))?;
        regions.push(StructuralRegion {
            name: "chunk_prefix_before_annexb".to_string(),
            offset: first_media_chunk.offset,
            len: prefix.len(),
            path: Some(prefix_path),
            notes: format!(
                "Prefix of chunk#{} before the first Annex-B start code",
                first_media_chunk.index
            ),
        });

        let tail = &first_bytes[annexb_offset..];
        let tail_path = structural_dir.join("chunk_tail_from_annexb.bin");
        fs::write(&tail_path, tail).with_context(|| format!("writing {}", tail_path.display()))?;
        regions.push(StructuralRegion {
            name: "chunk_tail_from_annexb".to_string(),
            offset: first_media_chunk.offset + annexb_offset,
            len: tail.len(),
            path: Some(tail_path),
            notes: format!(
                "Tail of chunk#{} starting at the first Annex-B boundary",
                first_media_chunk.index
            ),
        });
        annexb_tail_len = Some(tail.len());

        if let Some(continuation_stats) = &continuation {
            let mut joined = tail.to_vec();
            let continuation_bytes = fs::read(
                structural_dir.join("continuation_chunks.bin"),
            )
            .with_context(|| {
                format!(
                    "reading {}",
                    structural_dir.join("continuation_chunks.bin").display()
                )
            })?;
            joined.extend_from_slice(&continuation_bytes);
            let joined_path = structural_dir.join("annexb_plus_continuation.bin");
            fs::write(&joined_path, &joined)
                .with_context(|| format!("writing {}", joined_path.display()))?;
            regions.push(StructuralRegion {
                name: "annexb_plus_continuation".to_string(),
                offset: first_media_chunk.offset + annexb_offset,
                len: joined.len(),
                path: Some(joined_path),
                notes: format!(
                    "Annex-B tail joined with {} continuation chunks",
                    continuation_stats.count
                ),
            });
        }
    } else {
        notes.push(format!(
            "First media chunk chunk#{} did not contain an Annex-B start code",
            first_media_chunk.index
        ));
    }

    Ok(MediaStructureAnalysis {
        structural_dir,
        regions,
        continuation,
        annexb_tail_len,
        notes,
    })
}

pub(crate) fn build_extraction_candidates(
    analysis_artifacts_dir: &Path,
    media_blob: &[u8],
    chunks: &[MediaChunkEntry],
    media_structure: &MediaStructureAnalysis,
) -> Result<Vec<ExtractionCandidate>> {
    let extraction_dir = analysis_artifacts_dir.join("extraction_candidates");
    fs::create_dir_all(&extraction_dir)
        .with_context(|| format!("creating {}", extraction_dir.display()))?;

    let non_http = concat_non_http_chunks(media_blob, chunks);
    let first_media_chunk = chunks.iter().find(|chunk| !chunk.starts_with_http);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    if let Some(offset) = find_first_annexb(&non_http) {
        push_candidate(
            &mut candidates,
            &mut seen,
            &extraction_dir,
            "from_first_annexb",
            &non_http[offset..],
        )?;
    }

    if let Some(offset) = find_subsequence(&non_http, DHAV_MAGIC) {
        push_candidate(
            &mut candidates,
            &mut seen,
            &extraction_dir,
            "from_first_dhav",
            &non_http[offset..],
        )?;
        for &skip in HEADER_SKIP_CANDIDATES {
            if offset + skip < non_http.len() {
                push_candidate(
                    &mut candidates,
                    &mut seen,
                    &extraction_dir,
                    &format!("from_first_dhav_skip_{skip}"),
                    &non_http[offset + skip..],
                )?;
            }
        }
    }

    if let Some(chunk) = first_media_chunk {
        let bytes = &media_blob[chunk.offset..chunk.offset + chunk.len];
        if let Some(offset) = find_subsequence(bytes, DHAV_MAGIC) {
            for &skip in HEADER_SKIP_CANDIDATES {
                if offset + skip < bytes.len() {
                    push_candidate(
                        &mut candidates,
                        &mut seen,
                        &extraction_dir,
                        &format!("from_chunk{}_dhav_skip_{skip}", chunk.index),
                        &bytes[offset + skip..],
                    )?;
                }
            }
        }
    }

    push_structural_extraction_candidates(&mut candidates, &mut seen, &extraction_dir, media_structure)?;

    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(candidates)
}

fn push_structural_extraction_candidates(
    candidates: &mut Vec<ExtractionCandidate>,
    seen: &mut HashSet<String>,
    extraction_dir: &Path,
    media_structure: &MediaStructureAnalysis,
) -> Result<()> {
    for region in &media_structure.regions {
        let Some(path) = &region.path else {
            continue;
        };
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        push_candidate(
            candidates,
            seen,
            extraction_dir,
            &format!("structural_{}", region.name),
            &bytes,
        )?;
    }
    Ok(())
}

fn push_candidate(
    candidates: &mut Vec<ExtractionCandidate>,
    seen: &mut HashSet<String>,
    extraction_dir: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }

    let key = format!("{name}:{}:{}", bytes.len(), preview_hex(bytes, 24));
    if !seen.insert(key) {
        return Ok(());
    }

    let path = extraction_dir.join(format!("{name}.bin"));
    fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    let candidate = ExtractionCandidate {
        name: name.to_string(),
        path,
        bytes: bytes.len(),
        first_dhav_offset: find_subsequence(bytes, DHAV_MAGIC),
        first_annexb_offset: find_first_annexb(bytes),
        preview_hex: preview_hex(bytes, 24),
    };
    candidates.push(candidate);
    Ok(())
}
