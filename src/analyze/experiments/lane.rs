use crate::analyze::{
    experiment::{DecryptExperiment, ExperimentOutput, InclusionMode},
    model::{MediaStructureAnalysis, StructuredDataset},
    util::find_first_annexb_with_len,
};

pub(crate) struct LaneXorAfterAnnexBExperiment;

impl DecryptExperiment for LaneXorAfterAnnexBExperiment {
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
        for lane_count in [2usize, 4, 8] {
            for lane in 0..lane_count {
                for key in 0u8..=255 {
                    outputs.push(ExperimentOutput {
                        suffix: format!("lane{lane_count}_{lane}_xor_{key:02x}"),
                        xor_key: Some(key),
                        transform: format!("lane_xor_after_first_annexb/{lane_count}/{lane}"),
                        bytes: xor_after_first_annexb_by_lane(bytes, lane_count, lane, key),
                    });
                }
            }
        }
        outputs
    }
}

pub(crate) fn xor_after_first_annexb_by_lane(
    data: &[u8],
    lane_count: usize,
    lane: usize,
    key: u8,
) -> Vec<u8> {
    let Some((start_code_offset, start_code_len)) = find_first_annexb_with_len(data) else {
        return data.to_vec();
    };
    let mut out = data.to_vec();
    let payload_offset = start_code_offset + start_code_len;
    for (idx, byte) in out[payload_offset..].iter_mut().enumerate() {
        if idx % lane_count == lane {
            *byte ^= key;
        }
    }
    out
}
