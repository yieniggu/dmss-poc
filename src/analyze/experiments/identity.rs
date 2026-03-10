use crate::analyze::{
    experiment::{DecryptExperiment, ExperimentOutput, InclusionMode},
    model::{MediaStructureAnalysis, StructuredDataset},
};

pub(crate) struct IdentityExperiment;

impl DecryptExperiment for IdentityExperiment {
    fn inclusion_mode(&self) -> InclusionMode {
        InclusionMode::AlwaysInclude
    }

    fn generate(
        &self,
        _source: &StructuredDataset,
        bytes: &[u8],
        _media_structure: &MediaStructureAnalysis,
    ) -> Vec<ExperimentOutput> {
        vec![ExperimentOutput {
            suffix: "identity".to_string(),
            xor_key: None,
            transform: "identity".to_string(),
            bytes: bytes.to_vec(),
        }]
    }
}
