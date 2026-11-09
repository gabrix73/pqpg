use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::armor::decode_armored;
use crate::keys::PublicKey;

pub const ACTION_PUBLISH: u8 = 1;
pub const ACTION_LOOKUP: u8 = 2;
pub const ACTION_REVOKE: u8 = 3;
pub const ACTION_LIST: u8 = 4;

pub const DEFAULT_KEYSERVER_ADDR: &str = "127.0.0.1:9095";

#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub fingerprint: String,
    pub user_id: String,
    pub armored_public_key: String,
    pub signature: Vec<u8>,
    pub timestamp: i64,
    pub revoked: bool,
    pub revocation_reason: String,
}

#[derive(Debug, Clone)]
pub struct KeyRecordSummary {
    pub fingerprint: String,
    pub user_id: String,
    pub timestamp: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub action: u8,
    pub success: bool,
    pub error: Option<String>,
    pub key_record: Option<KeyRecord>,
    pub keys: Option<Vec<KeyRecordSummary>>,
}

/// Computes canonical SHA-256 fingerprint from armored public key
pub fn compute_fingerprint(armored: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(armored.as_bytes());
    hex::encode(hasher.finalize())
}

/// Formats the canonical string signed by the key owner for registration
pub fn signed_publish_payload(user_id: &str, armored_key: &str, timestamp: i64) -> Vec<u8> {
    format!("PQKEYS-PUBLISH-V1|{}|{}|{}", user_id, armored_key, timestamp).into_bytes()
}

/// Formats the canonical string signed by the key owner for revocation
pub fn signed_revoke_payload(fingerprint: &str, reason: &str, timestamp: i64) -> Vec<u8> {
    format!("PQKEYS-REVOKE-V1|{}|{}|{}", fingerprint, reason, timestamp).into_bytes()
}

/// Sends framed CBOR message (4-byte BE length prefix + payload)
fn send_framed(stream: &mut TcpStream, payload: &[u8]) -> Result<(), anyhow::Error> {
    let len_be = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len_be)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Receives framed CBOR message
fn recv_framed(stream: &mut TcpStream) -> Result<Vec<u8>, anyhow::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn connect_keyserver<A: ToSocketAddrs>(addr: A) -> Result<TcpStream, anyhow::Error> {
    let stream = TcpStream::connect_timeout(
        &addr.to_socket_addrs()?.next().ok_or_else(|| anyhow::anyhow!("Invalid address"))?,
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

fn execute_roundtrip(server: &str, req_val: Value) -> Result<Reply, anyhow::Error> {
    let mut stream = connect_keyserver(server)
        .map_err(|e| anyhow::anyhow!("Connecting to PQKeys daemon at {}: {}", server, e))?;

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&req_val, &mut cbor_bytes)?;

    send_framed(&mut stream, &cbor_bytes)?;
    let raw_reply = recv_framed(&mut stream)?;

    let reply_val: Value = ciborium::from_reader(raw_reply.as_slice())
        .map_err(|e| anyhow::anyhow!("Parsing CBOR reply: {}", e))?;

    parse_reply(reply_val)
}

fn parse_reply(val: Value) -> Result<Reply, anyhow::Error> {
    let map = match val {
        Value::Map(m) => m,
        _ => return Err(anyhow::anyhow!("Invalid reply format: expected CBOR map")),
    };

    let mut action: u8 = 0;
    let mut success: bool = false;
    let mut error: Option<String> = None;
    let mut key_record: Option<KeyRecord> = None;
    let mut keys: Option<Vec<KeyRecordSummary>> = None;

    for (k, v) in map {
        if let Value::Integer(int_key) = k {
            match int_key.try_into() {
                Ok(1) => {
                    if let Value::Integer(a) = v {
                        action = a.try_into().unwrap_or(0);
                    }
                }
                Ok(2) => {
                    if let Value::Bool(b) = v {
                        success = b;
                    }
                }
                Ok(3) => {
                    if let Value::Text(s) = v {
                        if !s.is_empty() {
                            error = Some(s);
                        }
                    }
                }
                Ok(4) => {
                    if let Value::Map(rec_map) = v {
                        key_record = Some(parse_key_record(rec_map)?);
                    }
                }
                Ok(5) => {
                    if let Value::Array(arr) = v {
                        let mut summaries = Vec::with_capacity(arr.len());
                        for item in arr {
                            if let Value::Map(m) = item {
                                summaries.push(parse_key_summary(m)?);
                            }
                        }
                        keys = Some(summaries);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(Reply {
        action,
        success,
        error,
        key_record,
        keys,
    })
}

fn parse_key_record(map: Vec<(Value, Value)>) -> Result<KeyRecord, anyhow::Error> {
    let mut fingerprint = String::new();
    let mut user_id = String::new();
    let mut armored_public_key = String::new();
    let mut signature = Vec::new();
    let mut timestamp: i64 = 0;
    let mut revoked = false;
    let mut revocation_reason = String::new();

    for (k, v) in map {
        if let Value::Integer(ik) = k {
            match ik.try_into() {
                Ok(1) => {
                    if let Value::Text(s) = v {
                        fingerprint = s;
                    }
                }
                Ok(2) => {
                    if let Value::Text(s) = v {
                        user_id = s;
                    }
                }
                Ok(3) => {
                    if let Value::Text(s) = v {
                        armored_public_key = s;
                    }
                }
                Ok(4) => {
                    if let Value::Bytes(b) = v {
                        signature = b;
                    }
                }
                Ok(5) => {
                    if let Value::Integer(i) = v {
                        timestamp = i.try_into().unwrap_or(0);
                    }
                }
                Ok(6) => {
                    if let Value::Bool(b) = v {
                        revoked = b;
                    }
                }
                Ok(7) => {
                    if let Value::Text(s) = v {
                        revocation_reason = s;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(KeyRecord {
        fingerprint,
        user_id,
        armored_public_key,
        signature,
        timestamp,
        revoked,
        revocation_reason,
    })
}

fn parse_key_summary(map: Vec<(Value, Value)>) -> Result<KeyRecordSummary, anyhow::Error> {
    let mut fingerprint = String::new();
    let mut user_id = String::new();
    let mut timestamp: i64 = 0;
    let mut revoked = false;

    for (k, v) in map {
        if let Value::Integer(ik) = k {
            match ik.try_into() {
                Ok(1) => {
                    if let Value::Text(s) = v {
                        fingerprint = s;
                    }
                }
                Ok(2) => {
                    if let Value::Text(s) = v {
                        user_id = s;
                    }
                }
                Ok(3) => {
                    if let Value::Integer(i) = v {
                        timestamp = i.try_into().unwrap_or(0);
                    }
                }
                Ok(4) => {
                    if let Value::Bool(b) = v {
                        revoked = b;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(KeyRecordSummary {
        fingerprint,
        user_id,
        timestamp,
        revoked,
    })
}

/// Zero-trust verification: verifies that the key record contains a valid self-signature
pub fn verify_key_record_self_signature(rec: &KeyRecord) -> Result<(), anyhow::Error> {
    let raw_pub = decode_armored(&rec.armored_public_key, "PUBLIC KEY")
        .map_err(|e| anyhow::anyhow!("Decoding armored public key: {}", e))?;

    let pub_key = PublicKey::from_bytes(&raw_pub)
        .map_err(|e| anyhow::anyhow!("Parsing public key structure: {}", e))?;

    let expected_payload = signed_publish_payload(&rec.user_id, &rec.armored_public_key, rec.timestamp);
    let sig = ed25519_dalek::Signature::from_slice(&rec.signature)
        .map_err(|e| anyhow::anyhow!("Malformed signature in key record: {}", e))?;

    pub_key.ed25519_pk.verify(&expected_payload, &sig)
        .map_err(|_| anyhow::anyhow!("Zero-trust verification failed: self-signature does not match key owner!"))?;

    Ok(())
}

/// Publishes a post-quantum public key to the Pigeonhole/Katzenpost PQKeys service
pub fn publish_key(
    server: &str,
    user_id: &str,
    armored_pub: &str,
    signing_key: &SigningKey,
) -> Result<KeyRecord, anyhow::Error> {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let payload_bytes = signed_publish_payload(user_id, armored_pub, ts);
    let sig = signing_key.sign(&payload_bytes).to_bytes().to_vec();

    let mut pub_fields = vec![
        (Value::Integer(2.into()), Value::Text(armored_pub.to_string())),
        (Value::Integer(3.into()), Value::Bytes(sig)),
        (Value::Integer(4.into()), Value::Integer(ts.into())),
    ];
    if !user_id.is_empty() {
        pub_fields.push((Value::Integer(1.into()), Value::Text(user_id.to_string())));
    }

    let req_val = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(ACTION_PUBLISH.into())),
        (Value::Integer(2.into()), Value::Map(pub_fields)),
    ]);

    let reply = execute_roundtrip(server, req_val)?;
    if !reply.success {
        return Err(anyhow::anyhow!(
            "PQKeys server rejected publish: {}",
            reply.error.unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    reply.key_record.ok_or_else(|| anyhow::anyhow!("Server returned success without KeyRecord"))
}

/// Queries a public key from Pigeonhole/Katzenpost PQKeys service and verifies its self-signature
pub fn lookup_key(server: &str, query: &str) -> Result<KeyRecord, anyhow::Error> {
    let req_val = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(ACTION_LOOKUP.into())),
        (Value::Integer(3.into()), Value::Map(vec![
            (Value::Integer(1.into()), Value::Text(query.to_string())),
        ])),
    ]);

    let reply = execute_roundtrip(server, req_val)?;
    if !reply.success {
        return Err(anyhow::anyhow!(
            "PQKeys lookup error: {}",
            reply.error.unwrap_or_else(|| "Key not found".to_string())
        ));
    }

    let rec = reply.key_record.ok_or_else(|| anyhow::anyhow!("Server returned success without KeyRecord"))?;
    verify_key_record_self_signature(&rec)?;
    Ok(rec)
}

/// Revokes a registered post-quantum public key using the owner's private signing key
pub fn revoke_key(
    server: &str,
    armored_pub: &str,
    signing_key: &SigningKey,
    reason: &str,
) -> Result<KeyRecord, anyhow::Error> {
    let fp = compute_fingerprint(armored_pub);
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let payload_bytes = signed_revoke_payload(&fp, reason, ts);
    let sig = signing_key.sign(&payload_bytes).to_bytes().to_vec();

    let req_val = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(ACTION_REVOKE.into())),
        (Value::Integer(4.into()), Value::Map(vec![
            (Value::Integer(1.into()), Value::Text(fp)),
            (Value::Integer(2.into()), Value::Text(reason.to_string())),
            (Value::Integer(3.into()), Value::Bytes(sig)),
            (Value::Integer(4.into()), Value::Integer(ts.into())),
        ])),
    ]);

    let reply = execute_roundtrip(server, req_val)?;
    if !reply.success {
        return Err(anyhow::anyhow!(
            "PQKeys revocation error: {}",
            reply.error.unwrap_or_else(|| "Failed to revoke key".to_string())
        ));
    }

    reply.key_record.ok_or_else(|| anyhow::anyhow!("Server returned success without KeyRecord"))
}

/// Lists summaries of registered public keys
pub fn list_keys(server: &str, limit: usize, offset: usize) -> Result<Vec<KeyRecordSummary>, anyhow::Error> {
    let req_val = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(ACTION_LIST.into())),
        (Value::Integer(5.into()), Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer((limit as u64).into())),
            (Value::Integer(2.into()), Value::Integer((offset as u64).into())),
        ])),
    ]);

    let reply = execute_roundtrip(server, req_val)?;
    if !reply.success {
        return Err(anyhow::anyhow!(
            "PQKeys list error: {}",
            reply.error.unwrap_or_else(|| "Failed to list keys".to_string())
        ));
    }

    Ok(reply.keys.unwrap_or_default())
}
