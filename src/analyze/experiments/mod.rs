mod identity;
mod lane;
mod repeating;
mod xor;

use super::experiment::DecryptExperiment;

pub(crate) fn registered_experiments() -> Vec<Box<dyn DecryptExperiment>> {
    vec![
        Box::new(identity::IdentityExperiment),
        Box::new(xor::XorAfterAnnexBExperiment),
        Box::new(lane::LaneXorAfterAnnexBExperiment),
        Box::new(repeating::HeaderGuidedRepeatingXorExperiment),
    ]
}

pub(crate) use xor::xor_after_first_annexb;
pub(crate) use lane::xor_after_first_annexb_by_lane;
pub(crate) use repeating::xor_after_first_annexb_with_repeating_header_key;
