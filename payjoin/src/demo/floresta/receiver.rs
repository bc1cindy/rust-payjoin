use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::pollard::{Pollard, PollardAddition};
use rustreexo::accumulator::proof::Proof;

/// Simplified Utreexo accumulator for payjoin receivers.
///
/// This wrapper maintains a minimal Pollard containing only the UTXOs
/// the receiver plans to contribute, enabling lightweight proof generation
/// without requiring full node infrastructure.
pub struct ReceiverUtreexo {
    pollard: Pollard<BitcoinNodeHash>,
}

impl ReceiverUtreexo {
    /// Creates a new accumulator initialized with the given leaves.
    ///
    /// - Uses `modify()` because it's the only way to add leaves to a Pollard
    /// - Empty proof is valid since we're starting from an empty accumulator
    /// - No deletions needed during initialization (empty `&[]`)
    /// - `remember: true` is critical, without it, we couldn't generate proofs later
    pub fn new(initial_leaves: Vec<BitcoinNodeHash>) -> Result<Self, String> {
        let mut pollard = Pollard::new();
        
        // Skip modification if there are no leaves to add
        // This avoids unnecessary operations and potential edge cases
        if !initial_leaves.is_empty() {
            // Mark all leaves as remembered so we can generate proofs for them
            // Without `remember: true`, the Pollard would discard these nodes
            // and prove_single() would fail
            let adds: Vec<PollardAddition<_>> = initial_leaves
                .into_iter()
                .map(|h| PollardAddition { hash: h, remember: true })
                .collect();
            
            pollard.modify(&adds, &[], Proof::default())
                .map_err(|e| format!("Failed to initialize pollard: {}", e))?;
        }
        
        Ok(Self { pollard })
    }
    
    /// Generates an inclusion proof for a specific leaf.
    ///
    /// The receiver must prove their contributed UTXO exists in the accumulator
    /// so the sender can verify it without running a full node. This proof
    /// gets attached to the payjoin PSBT.
    ///
    /// The leaf must have been added with `remember: true`, otherwise
    /// prove_single() will return an error since the node isn't cached.
    pub fn prove(&self, leaf: BitcoinNodeHash) -> Result<Proof<BitcoinNodeHash>, String> {
        self.pollard.prove_single(leaf)
    }
    
    /// Returns the current accumulator roots.
    ///
    /// Roots represent the compact cryptographic commitment to all leaves
    /// in the accumulator. 
    ///
    ///  This demo uses receiver's roots for simplicity, which is INSECURE.
    /// In production, the sender MUST use roots from their own full node or
    /// a trusted Utreexo bridge node. Accepting receiver's roots allows fraud.
    pub fn roots(&self) -> Vec<BitcoinNodeHash> {
        self.pollard.roots()
    }
}