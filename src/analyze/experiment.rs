use super::{
    model::MediaStructureAnalysis,
    model::{StructuredDataset, TOP_DECRYPT_CANDIDATES_PER_SOURCE},
};

pub(crate) enum InclusionMode {
    AlwaysInclude,
    Ranked,
}

pub(crate) struct ExperimentOutput {
    pub suffix: String,
    pub xor_key: Option<u8>,
    pub transform: String,
    pub bytes: Vec<u8>,
}

pub(crate) trait DecryptExperiment {
    fn inclusion_mode(&self) -> InclusionMode;
    fn generate(
        &self,
        source: &StructuredDataset,
        bytes: &[u8],
        media_structure: &MediaStructureAnalysis,
    ) -> Vec<ExperimentOutput>;
}

pub(crate) fn ranked_limit() -> usize {
    TOP_DECRYPT_CANDIDATES_PER_SOURCE
}
