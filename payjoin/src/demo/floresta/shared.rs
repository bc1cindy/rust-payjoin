use std::str::FromStr;

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Address, Amount, BlockHash, OutPoint, Psbt, TxOut, Txid, Witness};
use payjoin::psbt_ext::PsbtExt;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::proof::Proof;
use rustreexo::accumulator::stump::Stump;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// 2^i leaves for each root at position i
pub fn calculate_leaves_from_roots(roots: &[BitcoinNodeHash]) -> u64 {
    let mut leaves = 0u64;
    for (i, _) in roots.iter().enumerate() {
        leaves += 1 << i;
    }
    leaves
}

/// Computes the Utreexo leaf hash for a UTXO.
/// Concatenates outpoint, txout, and block_hash, then hashes with SHA512/256.
/// This creates the leaf node in the Utreexo accumulator tree.
pub fn compute_leaf(
    outpoint: &OutPoint,
    txout: &TxOut,
    block_hash: &BlockHash,
    header_code: u32,
) -> BitcoinNodeHash {
    let mut data = Vec::new();
    block_hash.consensus_encode(&mut data).unwrap();
    outpoint.consensus_encode(&mut data).unwrap();
    header_code.consensus_encode(&mut data).unwrap();
    txout.consensus_encode(&mut data).unwrap();

    BitcoinNodeHash::from(sha256::Hash::hash(&data).to_byte_array())
}

/// Returns a mock UTXO for testing/demo purposes.
/// Creates a deterministic outpoint (txid=0x01..01, vout=0) with 50,000 sats.
/// Uses the hardcoded receiver address on signet.
pub fn get_utxo() -> Result<(OutPoint, TxOut)> {
    let outpoint = OutPoint { txid: Txid::from_slice(&[1u8; 32])?, vout: 0 };

    let script_pubkey = Address::from_str("tb1qkxkzj3puteplnj5a0d4znhmdc2p62atxsmcj6c")?
        .assume_checked()
        .script_pubkey();

    let txout = TxOut { value: Amount::from_sat(50_000), script_pubkey };

    Ok((outpoint, txout))
}

/// Mock witness signature and pk for taproot demo
pub fn get_mock_p2wpkh_witness() -> Witness { Witness::from(vec![vec![0u8; 72], vec![0u8; 33]]) }

/// Serializes Utreexo roots into compact binary format.
pub fn serialize_roots(roots: &[BitcoinNodeHash]) -> Vec<u8> {
    let mut buf = (roots.len() as u32).to_le_bytes().to_vec();
    for root in roots {
        buf.extend_from_slice(root.as_ref());
    }
    buf
}

/// Deserializes Utreexo roots from binary format.
pub fn deserialize_roots(bytes: &[u8]) -> Result<Vec<BitcoinNodeHash>> {
    if bytes.len() < 4 {
        return Err("Invalid roots data".into());
    }
    let count = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    if bytes.len() != 4 + count * 32 {
        return Err("Invalid roots length".into());
    }
    (0..count)
        .map(|i| {
            let start = 4 + i * 32;
            Ok(BitcoinNodeHash::from(<[u8; 32]>::try_from(&bytes[start..start + 32])?))
        })
        .collect()
}

/// Extracts Utreexo roots from PSBT proprietary fields.
pub fn get_roots_from_psbt(psbt: &Psbt) -> Option<Vec<u8>> {
    psbt.proprietary
        .get(&bitcoin::psbt::raw::ProprietaryKey {
            prefix: b"utreexo".to_vec(),
            subtype: 0x01,
            key: vec![],
        })
        .cloned()
}

/// Verifies Utreexo proofs for specified inputs.
/// Sender has to generate his own trusted roots to verify
/// in this demo, it's using receiver's roots for simplicity
pub fn verify_proofs(
    psbt: &Psbt,
    positions: &[usize],
    stump: &Stump<BitcoinNodeHash>,
    block_hashes: &[BlockHash],
    header_codes: &[u32],
) -> Result<()> {
    for &idx in positions {
        let proof_bytes = psbt.get_utreexo_proof(idx).ok_or("Missing proof")?;
        let proof = Proof::deserialize(std::io::Cursor::new(proof_bytes))?;

        let txin = &psbt.unsigned_tx.input[idx];
        let txout = psbt.inputs[idx].witness_utxo.as_ref().ok_or("Missing witness_utxo")?;

        let leaf =
            compute_leaf(&txin.previous_output, txout, &block_hashes[idx], header_codes[idx]);

        let is_valid = stump
            .verify(&proof, &[leaf])
            .map_err(|e| format!("Proof verification error for input {}: {}", idx, e))?;

        if !is_valid {
            return Err(format!("Invalid inclusion proof for input {}", idx).into());
        }

        println!("  → Input {} verified successfully", idx);
    }
    Ok(())
}
