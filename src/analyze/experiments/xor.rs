use crate::analyze::{
    experiment::{DecryptExperiment, ExperimentOutput, InclusionMode},
    model::{HEADER_SKIP_CANDIDATES, MediaStructureAnalysis, StructuredDataset},
    util::find_first_annexb_with_len,
};

pub(crate) struct XorAfterAnnexBExperiment;

impl DecryptExperiment for XorAfterAnnexBExperiment {
    fn inclusion_mode(&self) -> InclusionMode {
        InclusionMode::Ranked
    }

    fn generate(
        &self,
        _source: &StructuredDataset,
        bytes: &[u8],
        _media_structure: &MediaStructureAnalysis,
    ) -> Vec<ExperimentOutput> {
        let mut outputs = Vec::new();
        for key in 0u8..=255 {
            outputs.push(ExperimentOutput {
                suffix: format!("xor_{key:02x}"),
                xor_key: Some(key),
                transform: "xor_after_first_annexb".to_string(),
                bytes: xor_after_first_annexb(bytes, key),
            });
        }

        for &skip in HEADER_SKIP_CANDIDATES {
            if skip >= bytes.len() {
                continue;
            }
            let slice = &bytes[skip..];
            for key in 0u8..=255 {
                outputs.push(ExperimentOutput {
                    suffix: format!("skip_{skip}_xor_{key:02x}"),
                    xor_key: Some(key),
                    transform: format!("xor_after_offset_{skip}"),
                    bytes: xor_after_first_annexb(slice, key),
                });
            }
        }

        outputs
    }
}

pub(crate) fn xor_after_first_annexb(data: &[u8], key: u8) -> Vec<u8> {
    let Some((start_code_offset, start_code_len)) = find_first_annexb_with_len(data) else {
        return data.to_vec();
    };
    let mut out = data.to_vec();
    let payload_offset = start_code_offset + start_code_len;
    for byte in &mut out[payload_offset..] {
        *byte ^= key;
    }
    out
}
