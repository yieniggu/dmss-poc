use std::path::PathBuf;

pub(crate) const DHAV_MAGIC: &[u8; 4] = b"DHAV";
pub(crate) const ANNEXB4: &[u8; 4] = b"\x00\x00\x00\x01";
pub(crate) const ANNEXB3: &[u8; 3] = b"\x00\x00\x01";
pub(crate) const HEADER_SKIP_CANDIDATES: &[usize] = &[0, 8, 16, 24, 32, 40, 46, 52, 64];
pub(crate) const TOP_DECRYPT_CANDIDATES_PER_SOURCE: usize = 16;
pub(crate) const MAX_HEVC_HEADERS_TO_SCORE: usize = 12;
pub(crate) const MAX_FFPROBE_CANDIDATES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpTrack {
    pub media: String,
    pub control: Option<String>,
    pub rtpmap: Option<String>,
    pub framerate: Option<String>,
    pub recvonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSdp {
    pub encrypt_alg: Option<String>,
    pub tracks: Vec<SdpTrack>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaChunkEntry {
    pub index: usize,
    pub offset: usize,
    pub len: usize,
    pub starts_with_http: bool,
    pub dhav_offset: Option<usize>,
    pub annexb_offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralRegion {
    pub name: String,
    pub offset: usize,
    pub len: usize,
    pub path: Option<PathBuf>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationChunkStats {
    pub first_index: usize,
    pub count: usize,
    pub common_len: Option<usize>,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaStructureAnalysis {
    pub structural_dir: PathBuf,
    pub regions: Vec<StructuralRegion>,
    pub continuation: Option<ContinuationChunkStats>,
    pub annexb_tail_len: Option<usize>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureAnalysis {
    pub core: CaptureCoreAnalysis,
    pub ffprobe_validation_path: PathBuf,
    pub ffprobe_results: Vec<CandidateProbeResult>,
    pub report_path: PathBuf,
    pub candidate_h265_path: Option<PathBuf>,
    pub playback_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureCoreAnalysis {
    pub capture_dir: PathBuf,
    pub headers: String,
    pub private_sdp_path: PathBuf,
    pub media_chunks_path: PathBuf,
    pub chunk_index_path: PathBuf,
    pub analysis_artifacts_dir: PathBuf,
    pub decrypt_candidates_dir: PathBuf,
    pub total_media_bytes: usize,
    pub first_dhav_offset: Option<usize>,
    pub first_annexb_offset: Option<usize>,
    pub sdp: ParsedSdp,
    pub chunks: Vec<MediaChunkEntry>,
    pub media_structure: MediaStructureAnalysis,
    pub extraction_candidates: Vec<ExtractionCandidate>,
    pub structured_datasets: Vec<StructuredDataset>,
    pub decrypt_candidates: Vec<DecryptCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateProbeResult {
    pub candidate_name: String,
    pub path: PathBuf,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceBlobSummary {
    pub name: String,
    pub path: PathBuf,
    pub bytes: usize,
    pub first_dhav_offset: Option<usize>,
    pub first_annexb_offset: Option<usize>,
    pub header_sample: Vec<HevcHeaderInfo>,
    pub preview_hex: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OracleCandidate {
    pub name: String,
    pub source_candidate: String,
    pub reference_name: String,
    pub path: PathBuf,
    pub bytes: usize,
    pub score: u32,
    pub method: String,
    pub preview_hex: String,
    pub match_ratio_per_mille: u32,
    pub hevc: Option<HevcHeaderInfo>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceComparison {
    pub analysis: CaptureAnalysis,
    pub reference_h264: ReferenceBlobSummary,
    pub reference_private: ReferenceBlobSummary,
    pub reference_raw_annexb: ReferenceBlobSummary,
    pub oracle_candidates_dir: PathBuf,
    pub oracle_candidates: Vec<OracleCandidate>,
    pub report_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionCandidate {
    pub name: String,
    pub path: PathBuf,
    pub bytes: usize,
    pub first_dhav_offset: Option<usize>,
    pub first_annexb_offset: Option<usize>,
    pub preview_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StructuredDatasetKind {
    HttpSdpOnly,
    DhavLeadingChunk,
    AnnexBTail,
    ContinuationChunks,
    AnnexBPlusContinuation,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredDataset {
    pub name: String,
    pub kind: StructuredDatasetKind,
    pub source_candidate: String,
    pub path: PathBuf,
    pub bytes: usize,
    pub first_dhav_offset: Option<usize>,
    pub first_annexb_offset: Option<usize>,
    pub preview_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HevcHeaderInfo {
    pub start_code_offset: usize,
    pub start_code_len: usize,
    pub nal_header_offset: usize,
    pub nal_unit_type: u8,
    pub temporal_id_plus1: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptCandidate {
    pub name: String,
    pub source_candidate: String,
    pub source_kind: StructuredDatasetKind,
    pub path: PathBuf,
    pub bytes: usize,
    pub xor_key: Option<u8>,
    pub transform: String,
    pub score: u32,
    pub continuity_bonus: i32,
    pub hevc: Option<HevcHeaderInfo>,
    pub header_sample: Vec<HevcHeaderInfo>,
    pub preview_hex: String,
}
