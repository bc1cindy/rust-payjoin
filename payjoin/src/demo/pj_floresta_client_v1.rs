use std::{fs, io::{self, Read, Write}, net::{TcpListener, TcpStream}, path::PathBuf, str::FromStr};
use bitcoin::{hashes::Hash, Address, BlockHash, Network, Psbt};
use floresta::{calculate_leaves_from_roots, deserialize_roots, get_roots_from_psbt, serialize_roots, 
    verify_proofs, receiver::ReceiverUtreexo};
use payjoin::{psbt_ext::PsbtExt, receive::v1::{build_v1_pj_uri, Headers, UncheckedOriginalPayload}, 
receive::InputPair, OutputSubstitution, Uri, UriExt};
use reqwest::{blocking::Client, header::{HeaderMap, HeaderValue, CONTENT_TYPE}};
use rustreexo::accumulator::stump::Stump;

mod floresta;

const RECEIVER_ADDRESS: &str = "tb1qkxkzj3puteplnj5a0d4znhmdc2p62atxsmcj6c";
const LISTEN_ADDR: &str = "127.0.0.1:4000";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("receiver") => receiver_server(),
        Some("sender") => {
            let path = std::env::args().nth(2).ok_or("Missing PSBT path")?;
            sender_client(PathBuf::from(path))
        }
        _ => {
            println!("\n=== FLORESTA PAYJOIN V1 CLIENT ===\n");
            println!("Features:");
            println!("  Synchronous HTTP-based payjoin protocol");
            println!("  Utreexo in PSBT proprietary fields");
            println!("  Direct peer-to-peer coordination\n");
            Ok(())
        }
    }
}

/// Minimal HTTP headers parser for payjoin V1 protocol.
/// Only extracts headers needed for payjoin coordination (Content-Type, Utreexo flag).
/// Important for receiver's utreexo detection, announced by sender
struct SimpleHeaders<'a>(&'a [u8]);

impl<'a> Headers for SimpleHeaders<'a> {
    fn get_header(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_ascii_lowercase();
        std::str::from_utf8(self.0)
            .ok()?
            .lines()
            .take_while(|line| !line.trim().is_empty())
            .find(|line| line.to_ascii_lowercase().starts_with(&format!("{key_lower}:")))
            .and_then(|line| line.split_once(':').map(|(_, v)| v.trim()))
    }
}

/// Starts the payjoin receiver HTTP server.
/// Listens for incoming payjoin requests and constructs collaborative transactions.
fn receiver_server() -> Result<()> {
    println!("\n=== PAYJOIN V1 RECEIVER ===\n");

    let addr = Address::from_str(RECEIVER_ADDRESS)?.require_network(Network::Signet)?;

    // Build payjoin URI with output substitution enabled for improved privacy
    let uri = build_v1_pj_uri(
        &addr,
        &format!("https://{LISTEN_ADDR}/pj"),
        OutputSubstitution::Enabled,
        true,
    )?;

    println!("Generated Payjoin URI:\n{uri}\n");
    println!("Starting HTTP server on {LISTEN_ADDR}");
    println!("Waiting for sender connection...\n");

    let listener = TcpListener::bind(LISTEN_ADDR)?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        println!("→ Incoming connection from {}", stream.peer_addr()?);

        if let Err(e) = handle_receiver(&mut stream, &addr) {
            eprintln!("✗ Error processing request: {e}");
            let _ = stream.write_all(format!("HTTP/1.1 500\r\n\r\n{e}").as_bytes());
        }
    }
    Ok(())
}

/// Handles a single payjoin request from a sender.
/// Validates the original PSBT, contributes receiver's input, and returns the payjoin proposal.
fn handle_receiver(stream: &mut TcpStream, receiver_addr: &Address) -> Result<()> {
    println!("Reading HTTP request...");
    let (headers_bytes, body) = read_http(stream)?;
    let headers = SimpleHeaders(&headers_bytes);

    // Check if sender supports Utreexo proofs
    let utreexo = headers.get_header("utreexo").is_some_and(|v| v == "1");
    println!("✓ Request received ({} bytes)", body.len());
    println!("  Utreexo support: {}", if utreexo { "enabled" } else { "disabled" });

    let query = format!("pj&v=1{}", if utreexo { "&utreexo=1" } else { "" });

    println!("Parsing original PSBT...");
    let payload = UncheckedOriginalPayload::from_request(&body, &query, headers)?;
    println!("✓ PSBT parsed successfully");

    println!("Validating sender's proposal...");
    // Payjoin validation chain:
    // 1. Interactive session 
    // 2. Verify sender doesn't control receiver's inputs
    // 3. Check inputs haven't been used before 
    // 4. Identify which outputs belong to receiver
    // 5. Commit to the output set
    let wants_inputs = payload
        .assume_interactive_receiver()
        .check_inputs_not_owned(&mut |s| Ok(s == &receiver_addr.script_pubkey()))?
        .check_no_inputs_seen_before(&mut |_| Ok(false))?
        .identify_receiver_outputs(&mut |s| Ok(s == &receiver_addr.script_pubkey()))?
        .commit_outputs();
    println!("✓ Validation passed");

    println!("Contributing receiver input...");
    let (outpoint, txout) = floresta::get_utxo()?;
    println!("  Selected UTXO: {}", outpoint);

    // Create receiver's input contribution
    let input_pair = InputPair::new(
        bitcoin::TxIn {
            previous_output: outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        },
        bitcoin::psbt::Input {
            witness_utxo: Some(txout),
            final_script_witness: Some(floresta::get_mock_p2wpkh_witness()),
            ..Default::default()
        },
        None,
    )?;

    println!("Finalizing payjoin proposal...");
    // Build the collaborative transaction:
    // 1. Add receiver's input
    // 2. Commit inputs 
    // 3. Apply fee adjustments
    // 4. Finalize the proposal PSBT
    let mut psbt = wants_inputs
        .contribute_inputs(vec![input_pair])?
        .commit_inputs()
        .apply_fee_range(None, None)?
        .finalize_proposal(|p| Ok(p.clone()))?
        .psbt()
        .clone();

    println!(
        "✓ Payjoin PSBT constructed ({} inputs, {} outputs)",
        psbt.unsigned_tx.input.len(),
        psbt.unsigned_tx.output.len()
    );

    // Attach Utreexo proof if sender requested it
    if utreexo {
        println!("Attaching Utreexo proof...");

        // Find the index of receiver's contributed input
        let idx = psbt
            .unsigned_tx
            .input
            .iter()
            .position(|tx| tx.previous_output == outpoint)
            .ok_or("input not found")?;

        // Compute the Utreexo leaf for this UTXO
        let leaf = floresta::compute_leaf(
            &outpoint,
            psbt.inputs[idx].witness_utxo.as_ref().unwrap(),
            &bitcoin::BlockHash::all_zeros(),
            0,
        );

        // Generate proof using a minimal accumulator containing only this UTXO
        let mut pollard = ReceiverUtreexo::new(vec![leaf])?;
        let roots = pollard.roots();

        let mut proof_bytes = Vec::new();
        pollard.prove(leaf)?.serialize(&mut proof_bytes);

        // Attach proof and roots to PSBT proprietary fields
        psbt.add_utreexo_proof(idx, proof_bytes.clone())?;
        psbt.add_utreexo_roots(serialize_roots(&roots))?;

        println!("✓ Attached Utreexo proof for input {} with {} root(s)", idx, roots.len());
        println!("  Proof size: {} bytes", proof_bytes.len());
    }

    println!("Sending payjoin proposal to sender...");
    send_http(stream, psbt.to_string())?;
    println!("✓ Payjoin V1 transaction completed successfully\n");

    Ok(())
}

/// Sends a payjoin request as the sender.
/// Constructs original PSBT, sends to receiver, validates the payjoin proposal.
fn sender_client(psbt_path: PathBuf) -> Result<()> {
    println!("\n=== PAYJOIN V1 SENDER ===\n");

    println!("Loading original PSBT from: {}", psbt_path.display());
    let original = Psbt::deserialize(&fs::read(&psbt_path)?)?;
    println!(
        "✓ PSBT loaded: {} inputs, {} outputs",
        original.unsigned_tx.input.len(),
        original.unsigned_tx.output.len()
    );

    println!("\nPaste receiver's Payjoin URI:");
    print!("> ");
    io::stdout().flush()?;

    let mut uri = String::new();
    io::stdin().read_line(&mut uri)?;

    println!("Parsing Payjoin URI...");
    let endpoint = Uri::from_str(uri.trim())?
        .assume_checked()
        .check_pj_supported()
        .map_err(|e| format!("Pj not supported: {e:?}"))?
        .extras
        .endpoint()
        // Convert HTTPS to HTTP for local testing
        .replace("HTTPS://", "http://")
        .replace("https://", "http://");

    println!("✓ Payjoin endpoint: {endpoint}");
    println!("Sending original PSBT to receiver...");

    // Build HTTP request with Utreexo support flag
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    headers.insert("utreexo", HeaderValue::from_static("1"));

    let response =
        Client::new().post(&endpoint).headers(headers).body(original.to_string()).send()?;

    println!("✓ Response received (HTTP {})", response.status());

    let proposal = Psbt::from_str(&response.text()?.trim().replace('\n', ""))?;

    println!(
        "✓ Payjoin proposal received: {} inputs, {} outputs",
        proposal.unsigned_tx.input.len(),
        proposal.unsigned_tx.output.len()
    );

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

    // Extract and verify accumulator roots
    println!("Extracting Utreexo roots from PSBT...");
    let roots = deserialize_roots(&get_roots_from_psbt(&proposal).ok_or("Missing roots")?)?;
    println!("✓ Found {} accumulator root(s)", roots.len());

    println!("Verifying Utreexo proofs...");
    let block_hashes = vec![BlockHash::all_zeros(); proposal.unsigned_tx.input.len()];
    let header_codes = vec![0u32; proposal.unsigned_tx.input.len()];
    let mut stump = Stump::new();
    stump.roots = roots;
    stump.leaves = calculate_leaves_from_roots(&stump.roots);
    verify_proofs(&proposal, &positions, &stump, &block_hashes, &header_codes)?;
    println!("✓ All proofs verified successfully!");

    // Save the final payjoin PSBT
    let final_path = psbt_path.with_file_name("payjoin_final.psbt");
    fs::write(&final_path, proposal.serialize())?;

    println!("\n✓ PAYJOIN V1 SENDER COMPLETED");
    println!("Final PSBT saved to: {}", final_path.display());
    println!("Total size: {} bytes\n", proposal.serialize().len());

    Ok(())
}

/// Reads HTTP request from TCP stream.
/// Continues reading until the header/body separator (\r\n\r\n) is found.
/// Returns separate header and body buffers for parsing.
fn read_http(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = [0u8; 8192];
    let mut req = Vec::new();

    // Read until we find the header terminator
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err("connection closed".into());
        }
        req.extend_from_slice(&buf[..n]);
        if req.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Split headers and body at the double CRLF
    let split = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    Ok((req[..split - 4].to_vec(), req[split..].to_vec()))
}

/// Sends HTTP 200 response with PSBT body.
/// Properly formats Content-Type and Content-Length headers.
/// Gracefully shuts down the connection after response.
fn send_http(stream: &mut TcpStream, body: String) -> Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Both)?;
    Ok(())
}