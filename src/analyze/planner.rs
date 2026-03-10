use super::model::{
    ExtractionCandidate, MediaStructureAnalysis, StructuredDataset, StructuredDatasetKind,
};

pub(crate) fn build_structured_datasets(
    extraction_candidates: &[ExtractionCandidate],
    _media_structure: &MediaStructureAnalysis,
) -> Vec<StructuredDataset> {
    let mut datasets = extraction_candidates
        .iter()
        .map(|candidate| StructuredDataset {
            name: candidate.name.clone(),
            kind: classify_candidate_kind(&candidate.name),
            source_candidate: candidate.name.clone(),
            path: candidate.path.clone(),
            bytes: candidate.bytes,
            first_dhav_offset: candidate.first_dhav_offset,
            first_annexb_offset: candidate.first_annexb_offset,
            preview_hex: candidate.preview_hex.clone(),
        })
        .collect::<Vec<_>>();
    datasets.sort_by(|a, b| {
        dataset_priority(a)
            .cmp(&dataset_priority(b))
            .then_with(|| a.name.cmp(&b.name))
    });
    datasets
}

pub(crate) fn plan_decrypt_datasets(
    datasets: &[StructuredDataset],
) -> Vec<StructuredDataset> {
    let mut planned = datasets
        .iter()
        .filter(|dataset| dataset.first_annexb_offset == Some(0))
        .cloned()
        .collect::<Vec<_>>();
    planned.sort_by(|a, b| {
        dataset_priority(a)
            .cmp(&dataset_priority(b))
            .then_with(|| a.name.cmp(&b.name))
    });
    planned.truncate(4);
    planned
}

fn classify_candidate_kind(name: &str) -> StructuredDatasetKind {
    if name.starts_with("structural_http_sdp") {
        StructuredDatasetKind::HttpSdpOnly
    } else if name.starts_with("structural_dhav_leading_chunk") {
        StructuredDatasetKind::DhavLeadingChunk
    } else if name.starts_with("structural_chunk_tail_from_annexb") {
        StructuredDatasetKind::AnnexBTail
    } else if name.starts_with("structural_continuation_chunks") {
        StructuredDatasetKind::ContinuationChunks
    } else if name.starts_with("structural_annexb_plus_continuation") {
        StructuredDatasetKind::AnnexBPlusContinuation
    } else {
        StructuredDatasetKind::Fallback
    }
}

fn dataset_priority(dataset: &StructuredDataset) -> (u8, usize) {
    let kind_rank = match dataset.kind {
        StructuredDatasetKind::AnnexBPlusContinuation => 0,
        StructuredDatasetKind::AnnexBTail => 1,
        StructuredDatasetKind::ContinuationChunks => 2,
        StructuredDatasetKind::DhavLeadingChunk => 3,
        StructuredDatasetKind::HttpSdpOnly => 4,
        StructuredDatasetKind::Fallback => 5,
    };
    (kind_rank, usize::MAX - dataset.bytes)
}
