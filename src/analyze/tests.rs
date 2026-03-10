use super::{analyze_capture_dir, decrypt::{candidate_score, first_hevc_header, hevc_sequence_bonus}, experiments::{xor_after_first_annexb, xor_after_first_annexb_with_repeating_header_key}, structure::parse_private_sdp};
use super::model::{ContinuationChunkStats, HevcHeaderInfo, MediaStructureAnalysis, StructuralRegion, StructuredDataset, StructuredDatasetKind};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn unique_temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{}_{}_{}", name, std::process::id(), nanos))
}

#[test]
fn parses_sdp_tracks() {
    let sdp = b"v=0\r\na=encryptalg:encrypt2\r\nm=video 0 RTP/AVP 98\r\na=control:trackID=0\r\na=rtpmap:98 H265/90000\r\na=recvonly\r\n";
    let parsed = parse_private_sdp(sdp).unwrap();
    assert_eq!(parsed.encrypt_alg.as_deref(), Some("encrypt2"));
    assert_eq!(parsed.tracks.len(), 1);
    assert_eq!(parsed.tracks[0].rtpmap.as_deref(), Some("98 H265/90000"));
}

#[test]
fn xor_candidate_can_make_first_hevc_header_plausible() {
    let encrypted = [0x00, 0x00, 0x00, 0x01, 0x42 ^ 0x41, 0x01 ^ 0x41, 0xaa ^ 0x41];
    let decoded = xor_after_first_annexb(&encrypted, 0x41);
    let header = first_hevc_header(&decoded).unwrap();
    assert_eq!(header.nal_unit_type, 33);
    assert_eq!(header.temporal_id_plus1, 1);
}

#[test]
fn repeating_xor_candidate_can_restore_first_hevc_header() {
    let encrypted = [
        0x00,
        0x00,
        0x00,
        0x01,
        0x42 ^ 0x41,
        0x01 ^ 0x42,
        0xaa ^ 0x41,
        0xbb ^ 0x42,
    ];
    let decoded =
        xor_after_first_annexb_with_repeating_header_key(&encrypted, 2, &[0x42, 0x01]);
    let header = first_hevc_header(&decoded).unwrap();
    assert_eq!(header.nal_unit_type, 33);
    assert_eq!(header.temporal_id_plus1, 1);
    assert_eq!(&decoded[4..8], &[0x42, 0x01, 0xaa, 0xbb]);
}

#[test]
fn sequence_bonus_prefers_ordered_parameter_sets() {
    let headers = vec![
        HevcHeaderInfo { start_code_offset: 0, start_code_len: 4, nal_header_offset: 4, nal_unit_type: 32, temporal_id_plus1: 1 },
        HevcHeaderInfo { start_code_offset: 8, start_code_len: 4, nal_header_offset: 12, nal_unit_type: 33, temporal_id_plus1: 1 },
        HevcHeaderInfo { start_code_offset: 16, start_code_len: 4, nal_header_offset: 20, nal_unit_type: 34, temporal_id_plus1: 1 },
    ];
    assert!(hevc_sequence_bonus(&headers) >= 30);
}

#[test]
fn candidate_score_rewards_vcl_after_parameter_sets() {
    let headers = vec![
        HevcHeaderInfo { start_code_offset: 0, start_code_len: 4, nal_header_offset: 4, nal_unit_type: 32, temporal_id_plus1: 1 },
        HevcHeaderInfo { start_code_offset: 8, start_code_len: 4, nal_header_offset: 12, nal_unit_type: 33, temporal_id_plus1: 1 },
        HevcHeaderInfo { start_code_offset: 16, start_code_len: 4, nal_header_offset: 20, nal_unit_type: 34, temporal_id_plus1: 1 },
        HevcHeaderInfo { start_code_offset: 24, start_code_len: 4, nal_header_offset: 28, nal_unit_type: 19, temporal_id_plus1: 1 },
    ];
    let media_structure = MediaStructureAnalysis {
        structural_dir: PathBuf::from("structural"),
        regions: vec![StructuralRegion {
            name: "annexb_plus_continuation".to_string(),
            offset: 0,
            len: 128,
            path: None,
            notes: String::new(),
        }],
        continuation: Some(ContinuationChunkStats {
            first_index: 2,
            count: 6,
            common_len: Some(1280),
            total_bytes: 7680,
        }),
        annexb_tail_len: Some(96),
        notes: vec![],
    };
    let dataset = StructuredDataset {
        name: "structural_annexb_plus_continuation".to_string(),
        kind: StructuredDatasetKind::AnnexBPlusContinuation,
        source_candidate: "structural_annexb_plus_continuation".to_string(),
        path: PathBuf::from("candidate.bin"),
        bytes: 128,
        first_dhav_offset: None,
        first_annexb_offset: Some(0),
        preview_hex: String::new(),
    };
    let score = candidate_score(&dataset, &headers, &media_structure);
    assert!(score >= 120);
}

#[test]
fn analyzes_capture_and_extracts_candidates() {
    let dir = unique_temp_dir("dmss_poc_analyze_capture");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("play_response_headers.txt"), b"HTTP/1.1 200 OK\r\nContent-Type: video/e-xav\r\n\r\n").unwrap();
    fs::write(
        dir.join("private_sdp.bin"),
        b"v=0\r\na=encryptalg:encrypt2\r\nm=video 0 RTP/AVP 98\r\na=control:trackID=0\r\na=rtpmap:98 H265/90000\r\na=recvonly\r\n",
    )
    .unwrap();
    let mut media = Vec::new();
    media.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
    media.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    media.extend_from_slice(b"DHAV");
    media.extend_from_slice(&[0; 42]);
    media.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0xaa, 0xbb]);
    media.extend_from_slice(&[0x11; 1280]);
    fs::write(dir.join("media_chunks.bin"), &media).unwrap();
    fs::write(
        dir.join("media_chunk_index.txt"),
        b"0 19\n1 60\n2 1280\n",
    )
    .unwrap();

    let analysis = analyze_capture_dir(&dir).unwrap();
    assert!(!analysis.core.extraction_candidates.is_empty());
    assert!(!analysis.core.structured_datasets.is_empty());
    assert!(!analysis.core.decrypt_candidates.is_empty());
    assert!(analysis.report_path.exists());

    let _ = fs::remove_dir_all(&dir);
}
