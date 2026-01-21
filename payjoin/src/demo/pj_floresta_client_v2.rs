use std::{fs, io::{self, Write}, path::PathBuf, str::FromStr, thread, time::Duration};
use bitcoin::{hashes::Hash, Address, BlockHash, FeeRate, Network, Psbt, ScriptBuf};
use floresta::{calculate_leaves_from_roots, deserialize_roots, get_roots_from_psbt, serialize_roots, verify_proofs};
use payjoin::{persist::OptionalTransitionOutcome, psbt_ext::PsbtExt, 
    receive::v2::{ReceiverBuilder, SessionEvent as RecvSessionEvent}, receive::InputPair, 
    send::v2::{SenderBuilder, SessionEvent as SendSessionEvent}, OhttpKeys, Uri, UriExt, ImplementationError};
use reqwest::blocking::Client;
use rustreexo::accumulator::stump::Stump;

mod floresta;

const RECEIVER_ADDRESS: &str = "tb1qkxkzj3puteplnj5a0d4znhmdc2p62atxsmcj6c";
const DIRECTORY_URL: &str = "http://localhost:3000";
const OHTTP_RELAY: &str = "http://localhost:3000";
const MAX_POLL_ATTEMPTS: u32 = 60;
const POLL_INTERVAL_SECS: u64 = 5;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("receiver") => receiver_flow(),
        Some("sender") => {
            let path = std::env::args().nth(2).ok_or("Missing PSBT path")?;
            sender_flow(PathBuf::from(path))
        }
        _ => {
            println!("\n=== FLORESTA PAYJOIN V2 CLIENT ===\n");
            println!("Features:");
            println!("  End-to-end OHTTP/HPKE encryption");
            println!("  Utreexo proofs in PSBT proprietary fields\n");
            Ok(())
        }
    }
}

/// Fetches OHTTP keys from the payjoin directory server.
/// These keys enable end-to-end encryption via Oblivious HTTP (OHTTP).
fn get_ohttp_keys() -> Result<OhttpKeys> {
    let response = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get(format!("{}/ohttp-keys", DIRECTORY_URL))
        .send()?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to fetch OHTTP keys (HTTP {}). Ensure payjoin-directory is running",
            response.status()
        )
        .into());
    }

    OhttpKeys::decode(&response.bytes()?).map_err(|e| format!("Invalid OHTTP keys: {}", e).into())
}

fn receiver_flow() -> Result<()> {
    println!("\n=== PAYJOIN V2 RECEIVER ===\n");

    let addr = Address::from_str(RECEIVER_ADDRESS)?.require_network(Network::Signet)?;

    // NoopSessionPersister is used for demo purposes only - does not persist state to disk.
    let persister = payjoin::persist::NoopSessionPersister::<RecvSessionEvent>::default();

    let receiver = ReceiverBuilder::new(addr.clone(), DIRECTORY_URL, get_ohttp_keys()?)
        .map_err(|e| format!("ReceiverBuilder error: {}", e))?
        .with_expiration(Duration::from_secs(3600))
        .with_utreexo(true)
        .build()
        .save(&persister)?;

    println!("Payjoin URI:\n{}\n", receiver.pj_uri());
    println!("Waiting for sender's proposal...");

    let unchecked_proposal = poll_for_proposal(&receiver, &persister)?;

    println!("Validating proposal...");
    // Payjoin validation chain: ensure inputs aren't owned by receiver,
    // haven't been seen before, identify receiver's outputs, and commit.
    let wants_inputs = unchecked_proposal
        .assume_interactive_receiver()
        .save(&persister)?
        .check_inputs_not_owned(&mut |script| Ok(script == &addr.script_pubkey()))
        .save(&persister)?
        .check_no_inputs_seen_before(&mut |_| Ok(false))
        .save(&persister)?
        .identify_receiver_outputs(&mut |s| Ok(s == &addr.script_pubkey()))
        .save(&persister)?
        .commit_outputs()
        .save(&persister)?;

    println!("✓ Validation passed");
    println!("Contributing receiver input...");

    // Create receiver's contribution to the payjoin transaction
    let (outpoint, txout) = floresta::get_utxo()?;
    let input_pair = InputPair::new(
        bitcoin::TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        },
        bitcoin::psbt::Input {
            witness_utxo: Some(txout.clone()),
            final_script_witness: Some(floresta::get_mock_p2wpkh_witness()),
            ..Default::default()
        },
        None,
    )?;

    let payjoin_proposal = wants_inputs
        .contribute_inputs(vec![input_pair])?
        .commit_inputs()
        .save(&persister)?
        .apply_fee_range(None, None)
        .save(&persister)?
        .finalize_proposal(|psbt| {
            let mut psbt = psbt.clone();
            let idx = psbt.unsigned_tx.input.iter()
                .position(|tx| tx.previous_output == outpoint)
                .ok_or_else(|| ImplementationError::from("input not found"))?;

            // Generate Utreexo proof for the receiver's contributed input
            let leaf =
                floresta::compute_leaf(&outpoint, &txout, &bitcoin::BlockHash::all_zeros(), 0);
            let mut pollard = floresta::receiver::ReceiverUtreexo::new(vec![leaf])
                .map_err(|e| ImplementationError::from(e.as_str()))?;
            let roots = pollard.roots();

            let mut proof_bytes = Vec::new();
            pollard.prove(leaf)
                .map_err(|e| ImplementationError::from(e.as_str()))?
                .serialize(&mut proof_bytes);

            println!(
                "[DEBUG] Before add: proof at input {}? {}, roots global? {}",
                idx,
                psbt.get_utreexo_proof(idx).is_some(),
                get_roots_from_psbt(&psbt).is_some()
            );

            // Attach Utreexo proof to the input and roots to global PSBT fields
            psbt.add_utreexo_proof(idx, proof_bytes)?;
            psbt.add_utreexo_roots(serialize_roots(&roots))?;

            println!(
                "[DEBUG] After add: proof at input {}? {} ({} bytes), roots? {} ({} bytes)",
                idx,
                psbt.get_utreexo_proof(idx).is_some(),
                psbt.get_utreexo_proof(idx).map_or(0, |b| b.len()),
                get_roots_from_psbt(&psbt).is_some(),
                get_roots_from_psbt(&psbt).map_or(0, |b| b.len())
            );

            println!("✓ Attached Utreexo proof with {} root(s)", roots.len());
            Ok(psbt)
        })
        .save(&persister)?;

    // BUG: NoopSessionPersister does NOT preserve PSBT proprietary fields.
    // The .save(&persister)? call above serializes/deserializes the session state,
    // but NoopSessionPersister doesn't actually persist to disk, it just validates
    // the serialization round-trip. During this process, custom PSBT fields
    // (including our Utreexo proofs and roots) are LOST because they're not part
    // of the core session state that gets serialized.
    //
    // This is why the verification fails on the sender side. The proofs disappear after
    // .save(&persister).
    //
    // Solution: I didn't test, but i believe the real persister preserves the full PSBT with
    // proprietary fields or if the lib is interested, it could be an issue to also
    // serialize proprietary fields in the NoopSessionPersister.
    let final_psbt = payjoin_proposal.psbt();
    let receiver_idx = final_psbt.unsigned_tx.input.iter()
        .position(|tx| tx.previous_output == outpoint)
        .ok_or("Receiver input not found in final PSBT")?;

    println!(
        "[DEBUG] After save: proof still at input {}? {} ({} bytes), roots? {} ({} bytes)",
        receiver_idx,
        final_psbt.get_utreexo_proof(receiver_idx).is_some(),
        final_psbt.get_utreexo_proof(receiver_idx).map_or(0, |v| v.len()),
        get_roots_from_psbt(final_psbt).is_some(),
        get_roots_from_psbt(final_psbt).map_or(0, |v| v.len())
    );
    println!(" WARNING: Proofs lost due to NoopSessionPersister limitations!");

    println!("Sending proposal to sender...");
    let (req, ctx) = payjoin_proposal.create_post_request(OHTTP_RELAY)?;
    let response = http_agent(OHTTP_RELAY, &req.body)?;
    payjoin_proposal.process_response(&response, ctx).save(&persister)?;

    println!("\n✓ PAYJOIN V2 RECEIVER COMPLETED\n");
    Ok(())
}

fn sender_flow(psbt_path: PathBuf) -> Result<()> {
    println!("\n=== PAYJOIN V2 SENDER ===\n");

    let persister = payjoin::persist::NoopSessionPersister::<SendSessionEvent>::default();
    let original = Psbt::deserialize(&fs::read(&psbt_path)?)?;

    println!(
        "Original PSBT: {} inputs, {} outputs",
        original.unsigned_tx.input.len(),
        original.unsigned_tx.output.len()
    );

    println!("\nPaste receiver's Payjoin URI:");
    print!("> ");
    io::stdout().flush()?;

    let mut uri_str = String::new();
    io::stdin().read_line(&mut uri_str)?;

    let pj_uri = Uri::from_str(uri_str.trim())?
        .assume_checked()
        .check_pj_supported()
        .map_err(|_| "Invalid Payjoin URI")?;

    println!("✓ URI valid (Utreexo: {})", pj_uri.extras.utreexo_enabled());

    let sender = SenderBuilder::new(original, pj_uri)
        .build_recommended(FeeRate::BROADCAST_MIN)?
        .save(&persister)?;

    println!("Sending original PSBT...");
    let (req, post_ctx) = sender.create_v2_post_request(OHTTP_RELAY)?;
    let response = http_agent(OHTTP_RELAY, &req.body)?;

    let polling_sender = sender.process_response(&response, post_ctx).save(&persister)?;

    println!("✓ Original PSBT sent");
    println!("Waiting for payjoin proposal...");

    let proposal = poll_for_final_psbt(&polling_sender, &persister)?;

    // Debug: inspect received PSBT structure
    let psbt_str = proposal.to_string();
    println!("[DEBUG] Received PSBT (first 500 chars):\n{}", &psbt_str[..500.min(psbt_str.len())]);
    println!("[DEBUG] PSBT has global roots? {}", get_roots_from_psbt(&proposal).is_some());
    println!("[DEBUG] PSBT has {} inputs", proposal.inputs.len());

    // Identify which inputs have Utreexo proofs attached
    let has_proofs: Vec<_> = (0..proposal.unsigned_tx.input.len())
        .filter_map(|i| {
            proposal.get_utreexo_proof(i).map(|p| {
                println!("  → Input {} has proof ({} bytes)", i, p.len());
                i
            })
        })
        .collect();

    if has_proofs.is_empty() {
        println!("  No inputs have utreexo proofs!");
        println!("    This is expected due to NoopSessionPersister stripping proprietary fields.");
        println!("    Verification will fail");
    }

    // Identify which inputs have Utreexo proofs
    println!("Checking for Utreexo proofs...");
    let positions: Vec<_> = (0..proposal.unsigned_tx.input.len())
        .filter(|&i| proposal.get_utreexo_proof(i).is_some())
        .collect();

    if positions.is_empty() {
        return Err("No Utreexo proofs found in payjoin proposal".into());
    }

    println!("✓ Found {} input(s) with Utreexo proofs", positions.len());
    for &idx in &positions {
        let proof_size = proposal.get_utreexo_proof(idx).unwrap().len();
        println!("  → Input {} has proof ({} bytes)", idx, proof_size);
    }

    // Extract and verify Utreexo roots (will fail because NoopSessionPersister was used)
    let roots =
        deserialize_roots(&get_roots_from_psbt(&proposal).ok_or("Missing Utreexo roots in PSBT")?)?;

    println!("Verifying Utreexo proofs...");
    let block_hashes = vec![BlockHash::all_zeros(); proposal.unsigned_tx.input.len()];
    let header_codes = vec![0u32; proposal.unsigned_tx.input.len()];
    let mut stump = Stump::new();
    stump.roots = roots;
    stump.leaves = calculate_leaves_from_roots(&stump.roots);
    verify_proofs(&proposal, &positions, &stump, &block_hashes, &header_codes)?;
    println!("✓ All proofs verified successfully!");

    let final_path = psbt_path.with_file_name("payjoin_v2_final.psbt");
    fs::write(&final_path, proposal.serialize())?;

    println!("\n✓ PAYJOIN V2 SENDER COMPLETED");
    println!("Final PSBT: {}", final_path.display());
    println!("({} bytes)\n", proposal.serialize().len());

    Ok(())
}

/// Polls the payjoin directory for the sender's original PSBT proposal.
/// Uses OHTTP for privacy, the directory cannot link sender to receiver.
/// Receiver: Initialized, poll_for_proposal(), UncheckedOriginalPayload
fn poll_for_proposal(
    receiver: &payjoin::receive::v2::Receiver<payjoin::receive::v2::Initialized>,
    persister: &payjoin::persist::NoopSessionPersister<RecvSessionEvent>,
) -> Result<payjoin::receive::v2::Receiver<payjoin::receive::v2::UncheckedOriginalPayload>> {
    for attempt in 1..=MAX_POLL_ATTEMPTS {
        if attempt > 1 {
            print!("\r[Poll {}/{}]", attempt, MAX_POLL_ATTEMPTS);
            io::stdout().flush()?;
        }

        let (req, ctx) = receiver.create_poll_request(OHTTP_RELAY)?;
        let response = http_agent(OHTTP_RELAY, &req.body)?;

        if !response.is_empty() {
            if let OptionalTransitionOutcome::Progress(proposal) =
                receiver.clone().process_response(&response, ctx).save(persister)?
            {
                if attempt > 1 {
                    println!();
                }
                println!("✓ Proposal received");
                return Ok(proposal);
            }
        }

        thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
    }

    Err("Timeout waiting for proposal".into())
}

/// Polls the payjoin directory for the receiver's payjoin proposal response.
/// The sender validates and potentially broadcasts this final PSBT.
/// Sender: PollingForProposal, poll_for_final_psbt(), Psbt (final)
fn poll_for_final_psbt(
    polling_sender: &payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>,
    persister: &payjoin::persist::NoopSessionPersister<SendSessionEvent>,
) -> Result<Psbt> {
    for attempt in 1..=MAX_POLL_ATTEMPTS {
        if attempt > 1 {
            print!("\r[Poll {}/{}]", attempt, MAX_POLL_ATTEMPTS);
            io::stdout().flush()?;
        }

        let (req, get_ctx) = polling_sender.create_poll_request(OHTTP_RELAY)?;
        let response = http_agent(OHTTP_RELAY, &req.body)?;

        if !response.is_empty() {
            match polling_sender.clone().process_response(&response, get_ctx).save(persister) {
                Ok(OptionalTransitionOutcome::Progress(psbt)) => {
                    if attempt > 1 {
                        println!();
                    }
                    println!("✓ Proposal received");
                    return Ok(psbt);
                }
                Ok(OptionalTransitionOutcome::Stasis(_)) => {}
                Err(e) => return Err(format!("Processing failed: {:#?}", e).into()),
            }
        }

        thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
    }

    Err("Timeout waiting for proposal".into())
}

/// Sends OHTTP-encrypted requests to the payjoin directory relay.
/// Returns empty vec for 404 (no data available yet), errors on other failures.
fn http_agent(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    let response = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .post(url)
        .header("Content-Type", "message/ohttp-req")
        .body(body.to_vec())
        .send()?;

    let status = response.status();

    // 404 means no proposal available yet, this is expected during polling
    if status.as_u16() == 404 {
        return Ok(vec![]);
    }

    if !status.is_success() {
        return Err(format!("HTTP {}", status).into());
    }

    Ok(response.bytes()?.to_vec())
}
