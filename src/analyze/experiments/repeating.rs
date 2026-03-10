use crate::analyze::{
    experiment::{DecryptExperiment, ExperimentOutput, InclusionMode},
    model::{MediaStructureAnalysis, StructuredDataset, StructuredDatasetKind},
    util::find_first_annexb_with_len,
};

pub(crate) struct HeaderGuidedRepeatingXorExperiment;

const EXPECTED_HEVC_HEADERS: &[(&str, &[u8])] = &[
    ("vps", &[0x40, 0x01]),
    ("sps", &[0x42, 0x01]),
    ("pps", &[0x44, 0x01]),
    ("idr", &[0x26, 0x01]),
    ("cra", &[0x2a, 0x01]),
    ("sei", &[0x4e, 0x01]),
];

const REPEATING_PERIODS: &[usize] = &[2, 4, 8, 16];

impl DecryptExperiment for HeaderGuidedRepeatingXorExperiment {
    fn inclusion_mode(&self) -> InclusionMode {
        InclusionMode::Ranked
    }

    fn generate(
        &self,
        source: &StructuredDataset,
        bytes: &[u8],
        _media_structure: &MediaStructureAnalysis,
    ) -> Vec<ExperimentOutput> {
        if !matches!(
            source.kind,
            StructuredDatasetKind::AnnexBTail | StructuredDatasetKind::AnnexBPlusContinuation
        ) {
            return Vec::new();
        }

        let Some((start_code_offset, start_code_len)) = find_first_annexb_with_len(bytes) else {
            return Vec::new();
        };
        let payload_offset = start_code_offset + start_code_len;
        if payload_offset + 2 > bytes.len() {
            return Vec::new();
        }

        let mut outputs = Vec::new();
        for &period in REPEATING_PERIODS {
            for &(label, expected_header) in EXPECTED_HEVC_HEADERS {
                let transformed = xor_after_first_annexb_with_repeating_header_key(
                    bytes,
                    period,
                    expected_header,
                );
                outputs.push(ExperimentOutput {
                    suffix: format!("repeat{period}_{label}"),
                    xor_key: None,
                    transform: format!("header_guided_repeating_xor/{period}/{label}"),
                    bytes: transformed,
                });
            }
        }

        outputs
    }
}

pub(crate) fn xor_after_first_annexb_with_repeating_header_key(
    data: &[u8],
    period: usize,
    expected_header: &[u8],
) -> Vec<u8> {
    let Some((start_code_offset, start_code_len)) = find_first_annexb_with_len(data) else {
        return data.to_vec();
    };
    let payload_offset = start_code_offset + start_code_len;
    if period == 0 || expected_header.is_empty() || payload_offset >= data.len() {
        return data.to_vec();
    }

    let mut key = vec![0u8; period];
    for i in 0..period {
        let observed = data.get(payload_offset + i).copied().unwrap_or(0);
        let expected = expected_header[i % expected_header.len()];
        key[i] = observed ^ expected;
    }

    let mut out = data.to_vec();
    for (idx, byte) in out[payload_offset..].iter_mut().enumerate() {
        *byte ^= key[idx % period];
    }
    out
}
