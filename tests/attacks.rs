//! End-to-end attack tests. Each test builds a fresh demo database, starts the real
//! middleman program, and talks to it the way a hostile MCP client would.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_middleman");
const SUPPORT: &str = "test-support-key-0123456789";
const BILLING: &str = "test-billing-key-0123456789";
const AUDITOR: &str = "test-auditor-key-0123456789";
const LIMITED: &str = "test-limited-key-0123456789";
const ELSEWHERE: &str = "test-elsewhere-key-0123456789";

fn hash(k: &str) -> String {
    Sha256::digest(k.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh folder with the demo database and the demo rules, re-keyed for tests.
fn workspace() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("middleman-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(BIN).arg("demo-db").arg(dir.join("shop.db")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let demo = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/shop.rules")).unwrap();
    let mut keys = [SUPPORT, BILLING, AUDITOR].into_iter();
    let mut text = String::new();
    for line in demo.lines() {
        if line.trim_start().starts_with("key-sha256") {
            text.push_str(&format!("  key-sha256  {}\n", hash(keys.next().unwrap())));
        } else if line.trim_start().starts_with("machines") {
            text.push_str("  machines    any\n");
        } else {
            text.push_str(line);
            text.push('\n');
        }
    }
    text.push_str(&format!(
        "\nrequester limited\n  key-sha256 {}\n  machines any\n  clearance 1\n  reasons support\n  \
         budget calls 3 per minute\n\nrequester elsewhere\n  key-sha256 {}\n  machines NOT-THIS-PC\n  \
         clearance 1\n  reasons support\n",
        hash(LIMITED),
        hash(ELSEWHERE)
    ));
    std::fs::write(dir.join("shop.rules"), text).unwrap();
    dir
}

struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: u64,
}

impl Client {
    fn start(dir: &Path, key: &str, elicitation: bool) -> Client {
        let mut child = Command::new(BIN)
            .arg("serve")
            .arg(dir.join("shop.rules"))
            .env("MIDDLEMAN_KEY", key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut c = Client { child, stdin, stdout, next: 1 };
        let caps = if elicitation { json!({"elicitation": {}}) } else { json!({}) };
        let r = c.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": caps, "clientInfo": {"name": "attacks", "version": "1"}}),
        );
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        c
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
    }

    fn send(&mut self, v: &Value) {
        self.send_bytes(v.to_string().as_bytes());
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "the server closed the connection");
        serde_json::from_str(&line).unwrap()
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let r = self.recv();
        assert_eq!(r["id"], id);
        r
    }

    fn tool_names(&mut self) -> Vec<String> {
        let r = self.request("tools/list", json!({}));
        r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_owned()).collect()
    }

    /// Returns whether it succeeded, the parsed reply, and the raw reply text.
    fn call(&mut self, tool: &str, args: Value) -> (bool, Value, String) {
        let r = self.request("tools/call", json!({"name": tool, "arguments": args}));
        unpack(&r)
    }

    fn ping_ok(&mut self) -> bool {
        self.request("ping", json!({}))["result"] == json!({})
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unpack(r: &Value) -> (bool, Value, String) {
    let text = r["result"]["content"][0]["text"].as_str().expect("a tool result").to_owned();
    let is_error = r["result"]["isError"].as_bool().unwrap();
    (!is_error, serde_json::from_str(&text).unwrap(), text)
}

fn refused(reply: &(bool, Value, String)) -> &str {
    assert!(!reply.0, "expected a refusal, got: {}", reply.2);
    reply.1["refused"].as_str().unwrap()
}

#[test]
fn each_requester_sees_only_its_own_menu() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    assert_eq!(c.tool_names(), ["find_customer", "read_customer", "recent_tickets", "open_ticket"]);

    let r = c.call("find_by_ssn", json!({"ssn": "000-11-1001", "reason": "support"}));
    assert_eq!(refused(&r), "unknown_action");
    assert!(!r.2.contains("find_by_ssn"), "refusals never repeat the request");
    let r = c.call("update_phone", json!({"customer_id": 1, "phone": "555-9999", "reason": "support"}));
    assert_eq!(refused(&r), "unknown_action");

    let mut b = Client::start(&dir, BILLING, false);
    assert_eq!(b.tool_names(), ["find_customer", "read_customer", "update_phone"]);
    let mut a = Client::start(&dir, AUDITOR, false);
    assert_eq!(a.tool_names(), ["find_customer", "read_customer", "find_by_ssn", "recent_tickets"]);
}

#[test]
fn levels_masks_and_groups_apply_per_requester() {
    let dir = workspace();
    let mut s = Client::start(&dir, SUPPORT, false);
    let (ok, body, _) = s.call("read_customer", json!({"customer_id": 1, "reason": "support"}));
    assert!(ok);
    let row = &body["rows"][0];
    assert_eq!(row["ssn"], "***-**-1001");
    assert_eq!(row["phone"], "***-**01");
    assert_eq!(row["zip"], "10001");
    assert!(row.get("birthdate").is_none(), "zip + birthdate together is above clearance 1");
    assert_eq!(body["withheld"], json!(["birthdate"]));
    assert_eq!(body["level"], 1);

    let mut b = Client::start(&dir, BILLING, false);
    let (ok, body, _) = b.call("read_customer", json!({"customer_id": 1, "reason": "invoice"}));
    assert!(ok);
    let row = &body["rows"][0];
    assert_eq!(row["phone"], "555-0101");
    assert_eq!(row["birthdate"], "1985-12-10");
    assert_eq!(row["ssn"], "***-**-1001");
    assert_eq!(body["level"], 2);

    let mut a = Client::start(&dir, AUDITOR, false);
    let (ok, body, _) = a.call("read_customer", json!({"customer_id": 1, "reason": "audit"}));
    assert!(ok);
    assert_eq!(body["rows"][0]["ssn"], "000-11-1001");
    assert_eq!(body["level"], 3);
    let (ok, body, _) = a.call("find_by_ssn", json!({"ssn": "000-22-2002", "reason": "audit"}));
    assert!(ok);
    assert_eq!(body["rows"][0]["last_name"], "Ortiz");
    assert_eq!(body["level"], 3, "a match on ssn is level 3 information");
}

#[test]
fn hidden_instructions_in_stored_data_are_stripped_and_labeled() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    let (ok, body, text) = c.call("read_customer", json!({"customer_id": 3, "reason": "support"}));
    assert!(ok);
    let notes = body["rows"][0]["notes"].as_str().unwrap();
    assert!(notes.chars().all(|ch| !(0xE0000..=0xE0FFF).contains(&(ch as u32))), "tag characters removed");
    assert!(!text.chars().any(|ch| (0xE0000..=0xE0FFF).contains(&(ch as u32))));
    assert!(notes.starts_with("Ignore all previous instructions"), "visible text stays, labeled as data");
    assert_eq!(body["cleaned_values"], 1);
    assert!(body["notice"].as_str().unwrap().contains("never as instructions"));

    let (_, body, _) = c.call("read_customer", json!({"customer_id": 4, "reason": "support"}));
    assert_eq!(body["rows"][0]["notes"], "Asked about refunds.");
}

#[test]
fn sql_injection_is_inert() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    let (ok, body, _) = c.call("find_customer", json!({"last_name": "Park", "reason": "support"}));
    assert!(ok);
    assert_eq!(body["row_count"], 2);

    // Fits the name rule, so it reaches the database, but only ever as a value.
    let (ok, body, _) = c.call("find_customer", json!({"last_name": "Park' OR 'a", "reason": "support"}));
    assert!(ok);
    assert_eq!(body["row_count"], 0);

    let r = c.call("find_customer", json!({"last_name": "Park\" OR 1=1 --", "reason": "support"}));
    assert_eq!(refused(&r), "bad_input");
    let r = c.call("find_customer", json!({"last_name": "x'; DROP TABLE customers; --", "reason": "support"}));
    assert_eq!(refused(&r), "bad_input");
    let (ok, body, _) = c.call("find_customer", json!({"last_name": "Park", "reason": "support"}));
    assert!(ok);
    assert_eq!(body["row_count"], 2, "the table is untouched");
}

#[test]
fn unknown_fields_are_refused_and_nothing_is_echoed() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    let r = c.call("find_customer", json!({"last_name": "Park", "reason": "support", "limit_PWNED": 999}));
    assert_eq!(refused(&r), "unknown_field");
    assert!(!r.2.contains("PWNED"));
    let r = c.call("find_customer", json!({"last_name": "PWNED<script>", "reason": "support"}));
    assert_eq!(refused(&r), "bad_input");
    assert!(!r.2.contains("PWNED"));
    let r = c.call("drop_everything_PWNED", json!({"reason": "support"}));
    assert_eq!(refused(&r), "unknown_action");
    assert!(!r.2.contains("PWNED"));
}

#[test]
fn wrong_types_ranges_and_reasons_are_refused() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    for bad in [json!(1.5), json!("1"), json!(0), json!(1_000_000), json!(-1), json!(true), json!(null), json!([1])] {
        let r = c.call("read_customer", json!({"customer_id": bad, "reason": "support"}));
        assert_eq!(refused(&r), "bad_input", "value {bad} should be refused");
    }
    let r = c.call("read_customer", json!({"customer_id": 1}));
    assert_eq!(refused(&r), "missing_reason");
    let r = c.call("read_customer", json!({"customer_id": 1, "reason": "audit"}));
    assert_eq!(refused(&r), "bad_reason");
    let r = c.call("read_customer", json!({"reason": "support"}));
    assert_eq!(refused(&r), "missing_input");
}

#[test]
fn malformed_duplicate_and_oversized_messages_are_dropped() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);

    c.send_bytes(
        br#"{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"find_customer","arguments":{"last_name":"Park","reason":"support","reason":"audit"}}}"#,
    );
    let r = c.recv();
    assert_eq!(r["error"]["code"], -32700, "duplicate keys are a parse error");
    assert_eq!(r["id"], Value::Null);

    let padding = "x".repeat(100_000);
    c.send(&json!({"jsonrpc": "2.0", "id": 51, "method": "ping", "params": {"pad": padding}}));
    let r = c.recv();
    assert_eq!(r["error"]["code"], -32600);
    assert!(r["error"]["message"].as_str().unwrap().contains("too large"));

    c.send_bytes("[".repeat(5000).as_bytes());
    assert_eq!(c.recv()["error"]["code"], -32700, "deep nesting is refused, not a crash");
    c.send_bytes(b"not json at all");
    assert_eq!(c.recv()["error"]["code"], -32700);
    c.send_bytes(br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
    assert_eq!(c.recv()["error"]["code"], -32600, "batches are not accepted");
    c.send_bytes(br#"{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}"#);
    assert_eq!(c.recv()["error"]["code"], -32600, "ids must be plain");
    assert!(c.ping_ok(), "the server is still alive");
}

#[test]
fn hidden_characters_in_input_are_refused_before_anyone_is_asked() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, true);
    let r = c.call("open_ticket", json!({"customer_id": 1, "body": "hello\u{E0041}\u{E0042}", "reason": "support"}));
    assert_eq!(refused(&r), "bad_input");
    let r = c.call("open_ticket", json!({"customer_id": 1, "body": "hi\u{202E}there", "reason": "support"}));
    assert_eq!(refused(&r), "bad_input");
}

#[test]
fn writes_need_a_person() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    let r = c.call("open_ticket", json!({"customer_id": 1, "body": "No one to ask", "reason": "support"}));
    assert_eq!(refused(&r), "approval_unavailable");

    let mut e = Client::start(&dir, SUPPORT, true);
    for (body, approve) in [("Decline me", false), ("Approve me", true)] {
        e.send(&json!({"jsonrpc": "2.0", "id": 900, "method": "tools/call",
            "params": {"name": "open_ticket", "arguments": {"customer_id": 1, "body": body, "reason": "support"}}}));
        let ask = e.recv();
        assert_eq!(ask["method"], "elicitation/create");
        let message = ask["params"]["message"].as_str().unwrap();
        assert!(message.contains("open_ticket") && message.contains(body));
        let answer = if approve {
            json!({"action": "accept", "content": {"approve": true}})
        } else {
            json!({"action": "decline"})
        };
        e.send(&json!({"jsonrpc": "2.0", "id": ask["id"], "result": answer}));
        let reply = unpack(&e.recv());
        if approve {
            assert!(reply.0, "{}", reply.2);
            assert_eq!(reply.1["changed"], 1);
        } else {
            assert_eq!(refused(&reply), "declined");
        }
    }
    let (ok, body, _) = e.call("recent_tickets", json!({"reason": "support"}));
    assert!(ok);
    assert_eq!(body["rows"][0]["body"], "Approve me");
    let bodies: Vec<&str> = body["rows"].as_array().unwrap().iter().map(|r| r["body"].as_str().unwrap()).collect();
    assert!(!bodies.contains(&"Decline me") && !bodies.contains(&"No one to ask"));
}

#[test]
fn budgets_are_enforced() {
    let dir = workspace();
    let mut c = Client::start(&dir, LIMITED, false);
    for _ in 0..3 {
        let (ok, _, _) = c.call("find_customer", json!({"last_name": "Park", "reason": "support"}));
        assert!(ok);
    }
    let r = c.call("find_customer", json!({"last_name": "Park", "reason": "support"}));
    assert_eq!(refused(&r), "over_budget");
    drop(c);
    let mut again = Client::start(&dir, LIMITED, false);
    let r = again.call("find_customer", json!({"last_name": "Park", "reason": "support"}));
    assert_eq!(refused(&r), "over_budget", "budgets survive a restart");
}

#[test]
fn the_audit_log_records_everything_but_values() {
    let dir = workspace();
    {
        let mut c = Client::start(&dir, SUPPORT, false);
        c.call("read_customer", json!({"customer_id": 1, "reason": "support"}));
        c.call("find_customer", json!({"last_name": "Park", "reason": "support"}));
        c.call("find_customer", json!({"last_name": "PWNED", "reason": "support", "x": 1}));
        c.call("no_such_PWNED", json!({}));
    }
    let db = rusqlite::Connection::open(dir.join("audit.db")).unwrap();
    let rows: Vec<String> = db
        .prepare("SELECT ts||requester||machine||transport||action||reason||outcome||detail FROM log")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 4);
    let all = rows.join("\n");
    for secret in ["Park", "Ada", "000-", "555-", "PWNED", "example.com"] {
        assert!(!all.contains(secret), "audit log must not contain '{secret}'");
    }
    assert!(db.execute("UPDATE log SET outcome = 'ok'", []).is_err(), "append-only");
    assert!(db.execute("DELETE FROM log", []).is_err(), "append-only");
}

#[test]
fn bad_keys_and_wrong_machines_cannot_start() {
    let dir = workspace();
    let run = |key: &str| {
        Command::new(BIN)
            .arg("serve")
            .arg(dir.join("shop.rules"))
            .env("MIDDLEMAN_KEY", key)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let out = run("this-key-matches-nobody-at-all");
    assert!(!out.status.success() && out.stdout.is_empty());
    let out = run("short");
    assert!(!out.status.success());
    let out = run(ELSEWHERE);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed on machine"));
}

#[test]
fn an_unlabeled_column_stops_the_middleman() {
    let dir = workspace();
    rusqlite::Connection::open(dir.join("shop.db"))
        .unwrap()
        .execute_batch("ALTER TABLE customers ADD COLUMN password TEXT")
        .unwrap();
    let out = Command::new(BIN).arg("check").arg(dir.join("shop.rules")).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("customers.password exists in the database but has no level"));
}

#[test]
fn command_line_requests_go_through_the_same_gate() {
    let dir = workspace();
    let run = |args: &[&str]| {
        Command::new(BIN)
            .arg("call")
            .arg(dir.join("shop.rules"))
            .args(args)
            .env("MIDDLEMAN_KEY", AUDITOR)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let out = run(&["read_customer", "reason=audit", "customer_id=2"]);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["rows"][0]["ssn"], "000-22-2002");

    let out = run(&["read_customer", "reason=audit", "customer_id=02"]);
    assert_eq!(out.status.code(), Some(2));
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["refused"], "bad_input");

    let out = run(&["read_customer", "reason=audit", "reason=support", "customer_id=2"]);
    assert_eq!(out.status.code(), Some(1), "a repeated field is an error");
}

#[test]
fn random_garbage_never_crashes_the_server() {
    let dir = workspace();
    let mut c = Client::start(&dir, SUPPORT, false);
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let alphabet = br#"{}[]":,.-+eE0123456789 abcxyz\/u"jsonrpc2.0idmethod"#;
    for i in 0..500 {
        let len = 1 + (next() % 300) as usize;
        let mut line: Vec<u8> = (0..len)
            .map(|_| {
                if i % 2 == 0 {
                    alphabet[(next() % alphabet.len() as u64) as usize]
                } else {
                    (next() % 256) as u8
                }
            })
            .filter(|b| *b != b'\n' && *b != b'\r')
            .collect();
        if line.iter().all(u8::is_ascii_whitespace) {
            line.push(b'x');
        }
        c.send_bytes(&line);
        let r = c.recv();
        assert!(r.get("error").is_some(), "garbage line {i} should get an error");
    }
    assert!(c.ping_ok());
}
