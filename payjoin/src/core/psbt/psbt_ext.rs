//! PSBT Extension Utilities
//!
//! Public trait for extending [`bitcoin::Psbt`] with helper methods like Utreexo proofs.

use std::collections::BTreeMap;

use bitcoin::{bip32, psbt};

use crate::core::psbt::{InconsistentPsbt, InternalInputPair, PsbtInputsError};

/// Extension trait for PSBT utilities
pub trait PsbtExt: Sized {
    /// Mutable access to PSBT inputs
    fn inputs_mut(&mut self) -> &mut [psbt::Input];
    /// Mutable access to PSBT outputs
    fn outputs_mut(&mut self) -> &mut [psbt::Output];
    /// Mutable access to xpub map
    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)>;
    /// Mutable access to proprietary fields
    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    /// Mutable access to unknown fields
    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;
    /// Iterator over paired inputs
    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_>;
    /// Validates PSBT structure
    fn validate(self) -> Result<Self, InconsistentPsbt>;
    /// Validates PSBT input UTXOs
    fn validate_input_utxos(&self) -> Result<(), PsbtInputsError>;

    /// Attaches a Utreexo inclusion proof to a specific PSBT input.
    ///
    /// Stores the serialized proof in the input's proprietary fields using the
    /// "utreexo" prefix with subtype 0x00. This allows the sender to verify that
    /// the UTXO exists in the receiver's accumulator without requiring full node data.
    ///
    /// The proof is stored per-input because each UTXO requires its own inclusion proof
    /// to demonstrate it exists in the Utreexo accumulator at the time of spending.
    fn add_utreexo_proof(
        &mut self,
        input_index: usize,
        proof: Vec<u8>,
    ) -> Result<(), &'static str> {
        if input_index >= self.inputs_mut().len() {
            return Err("Input index out of bounds");
        }

        let key =
            psbt::raw::ProprietaryKey { prefix: b"utreexo".to_vec(), subtype: 0x00, key: vec![] };

        self.inputs_mut()[input_index].proprietary.insert(key, proof);

        Ok(())
    }

    /// Retrieves a Utreexo proof from a specific PSBT input.
    ///
    /// Extracts the serialized proof from the input's proprietary fields.
    /// Returns None if no proof exists for this input, which is expected for
    /// sender-contributed inputs (only receiver inputs need proofs).
    ///
    /// Uses subtype 0x00 to distinguish proofs (per-input) from roots (global for demo).
    fn get_utreexo_proof(&self, input_index: usize) -> Option<Vec<u8>> {
        let key =
            psbt::raw::ProprietaryKey { prefix: b"utreexo".to_vec(), subtype: 0x00, key: vec![] };

        self.input_pairs()
            .nth(input_index)
            .and_then(|pair| pair.psbtin.proprietary.get(&key).cloned())
    }

    /// Attaches Utreexo accumulator roots to the PSBT fields.
    ///
    /// Stores the serialized roots using subtype 0x01 to distinguish them from
    /// per-input proofs (subtype 0x00). The roots represent the accumulator state
    /// and are required by the sender to verify all attached proofs.
    ///
    /// ! Sender has to generate trusted roots to verify, so they dont need to be here, 
    /// Adding to simplify and educational purpose.
    fn add_utreexo_roots(&mut self, roots: Vec<u8>) -> Result<(), &'static str> {
        let key =
            psbt::raw::ProprietaryKey { prefix: b"utreexo".to_vec(), subtype: 0x01, key: vec![] };

        self.proprietary_mut().insert(key, roots);
        Ok(())
    }
}

// Blanket implementation for bitcoin::Psbt
impl PsbtExt for bitcoin::Psbt {
    fn inputs_mut(&mut self) -> &mut [psbt::Input] { &mut self.inputs }
    fn outputs_mut(&mut self) -> &mut [psbt::Output] { &mut self.outputs }
    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)> {
        &mut self.xpub
    }
    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }
    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }
    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_> {
        Box::new(
            self.unsigned_tx
                .input
                .iter()
                .zip(&self.inputs)
                .map(|(txin, psbtin)| InternalInputPair { txin, psbtin }),
        )
    }
    fn validate(self) -> Result<Self, InconsistentPsbt> {
        let tx_ins = self.unsigned_tx.input.len();
        let psbt_ins = self.inputs.len();
        let tx_outs = self.unsigned_tx.output.len();
        let psbt_outs = self.outputs.len();

        if psbt_ins != tx_ins {
            Err(InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins })
        } else if psbt_outs != tx_outs {
            Err(InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs })
        } else {
            Ok(self)
        }
    }
    fn validate_input_utxos(&self) -> Result<(), PsbtInputsError> {
        self.input_pairs().enumerate().try_for_each(|(index, input)| {
            input.validate_utxo().map_err(|error| PsbtInputsError { index, error })
        })
    }
}
