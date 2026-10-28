//! The middleman: a gatekeeper that rips up every data request and rebuilds it
//! from an approved menu. See README.md for the rules language.

mod audit;
mod engine;
mod inputs;
mod mcp;
mod rules;
mod strict_json;

use engine::{Approval, Approver, Engine};
use rules::{Kind, Offer, Show};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
middleman: rips up every data request and rebuilds it from an approved menu.

usage:
  middleman serve <rules>                       run as an MCP server on stdin and stdout
  middleman call <rules> <action> name=value... run one request; reason=... is required
  middleman check <rules>                       check the rules and print every requester's menu
  middleman log <rules> [count]                 show the newest audit log entries
  middleman hash-key                            read a key from stdin, print its key-sha256
  middleman demo-db <path>                      create the demo database

The requester is identified by its key, read from the MIDDLEMAN_KEY environment variable.";

const DEMO_SEED: &str = include_str!("../examples/seed.sql");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") if args.len() == 2 => serve(&args[1]),
        Some("call") if args.len() >= 3 => call(&args[1], &args[2], &args[3..]),
        Some("check") if args.len() == 2 => check(&args[1]),
        Some("log") if args.len() == 2 || args.len() == 3 => log(&args[1], args.get(2)),
        Some("hash-key") if args.len() == 1 => hash_key(),
        Some("demo-db") if args.len() == 2 => demo_db(&args[1]),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

fn open(rules_path: &str) -> Result<Engine, String> {
    let rules = rules::load(Path::new(rules_path))?;
    Engine::open(rules)
}

fn key_from_env() -> Result<String, String> {
    std::env::var("MIDDLEMAN_KEY").map_err(|_| "set MIDDLEMAN_KEY to the requester's key".to_owned())
}

fn serve(rules_path: &str) -> Result<ExitCode, String> {
    let engine = open(rules_path)?;
    let gate = engine.gate(&key_from_env()?, "mcp-stdio")?;
    eprintln!(
        "middleman: serving '{}' on {} with {} action(s)",
        gate.tags.requester,
        gate.tags.machine,
        gate.items().count()
    );
    mcp::serve(&gate).map_err(|e| format!("middleman: connection failed: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

/// Asks the person at the terminal. If there is no terminal, no one can be asked.
struct TerminalApprover;

impl Approver for TerminalApprover {
    fn ask(&mut self, summary: &str) -> Approval {
        if !io::stdin().is_terminal() {
            return Approval::Unavailable;
        }
        eprintln!("\n{summary}\nType yes to approve: ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        match io::stdin().lock().read_line(&mut line) {
            Ok(_) if line.trim() == "yes" => Approval::Approved,
            _ => Approval::Declined,
        }
    }
}

fn call(rules_path: &str, action: &str, pairs: &[String]) -> Result<ExitCode, String> {
    let engine = open(rules_path)?;
    let gate = engine.gate(&key_from_env()?, "cli")?;
    let mut parsed = Vec::new();
    for p in pairs {
        let (k, v) = p.split_once('=').ok_or_else(|| format!("'{p}' should look like name=value"))?;
        parsed.push((k.to_owned(), v.to_owned()));
    }
    let args = gate.args_from_cli(action, &parsed)?;
    let reply = gate.call(action, &args, &mut TerminalApprover);
    println!("{}", serde_json::to_string_pretty(&reply.body).unwrap_or_default());
    Ok(if reply.ok { ExitCode::SUCCESS } else { ExitCode::from(2) })
}

fn check(rules_path: &str) -> Result<ExitCode, String> {
    let engine = open(rules_path)?;
    let r = &engine.rules;
    println!("Rules OK. Every column in every guarded table has a level.");
    println!("database: {}", r.database.display());
    println!("audit log: {}\n", r.audit.display());
    for req in &r.requesters {
        let machines = req.machines.as_ref().map(|m| m.join(", ")).unwrap_or_else(|| "any".into());
        println!(
            "requester {}  clearance {} ({})  reasons: {}  machines: {}",
            req.name,
            req.clearance,
            r.level_name(req.clearance),
            req.reasons.join(", "),
            machines
        );
        for b in &req.budgets {
            let what = if b.kind == rules::BudgetKind::Calls { "calls" } else { "rows" };
            let per = match b.window_secs {
                60 => "minute",
                3600 => "hour",
                _ => "day",
            };
            println!("  budget: {} {what} per {per}", b.limit);
        }
        for (i, a) in r.actions.iter().enumerate() {
            match r.offer(req, i) {
                Offer::Yes(item) => {
                    let mut line = format!("  CAN  {:<16} {} {}", a.name, a.kind.word(), a.table);
                    if a.kind == Kind::Read {
                        let seen: Vec<String> = item
                            .view
                            .iter()
                            .filter_map(|v| match v.show {
                                Show::Full => Some(v.column.clone()),
                                Show::Masked(m) => Some(format!("{} ({})", v.column, m.describe())),
                                Show::Withheld => None,
                            })
                            .collect();
                        let withheld: Vec<&str> = item
                            .view
                            .iter()
                            .filter(|v| v.show == Show::Withheld)
                            .map(|v| v.column.as_str())
                            .collect();
                        line.push_str(&format!("\n         sees: {}", seen.join(", ")));
                        if !withheld.is_empty() {
                            line.push_str(&format!("\n         withheld: {}", withheld.join(", ")));
                        }
                        line.push_str(&format!(
                            "\n         reply level {} ({})",
                            item.reply_level,
                            r.level_name(item.reply_level)
                        ));
                    } else {
                        let cols: Vec<&str> = a.sets.iter().map(|(c, _)| c.as_str()).collect();
                        line.push_str(&format!("\n         writes: {}", cols.join(", ")));
                    }
                    line.push_str(&format!("\n         reasons: {}", item.reasons.join(", ")));
                    if a.confirm {
                        line.push_str("\n         needs a person's approval");
                    }
                    println!("{line}");
                }
                Offer::No(why) => println!("  NOT  {:<16} {why}", a.name),
            }
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

fn log(rules_path: &str, count: Option<&String>) -> Result<ExitCode, String> {
    let engine = open(rules_path)?;
    let n = match count {
        Some(c) => c.parse::<usize>().map_err(|_| "count must be a number".to_owned())?,
        None => 20,
    };
    for line in engine.audit().recent(n.min(10_000))? {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}

fn hash_key() -> Result<ExitCode, String> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
    let key = line.trim_end_matches(['\r', '\n']);
    if key.chars().count() < engine::MIN_KEY_LEN {
        return Err(format!("the key must be at least {} characters", engine::MIN_KEY_LEN));
    }
    println!("{}", engine::hex(&engine::hash_key(key)));
    Ok(ExitCode::SUCCESS)
}

fn demo_db(path: &str) -> Result<ExitCode, String> {
    if Path::new(path).exists() {
        return Err(format!("{path} already exists; delete it first to rebuild the demo"));
    }
    let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch(DEMO_SEED).map_err(|e| format!("cannot build demo database: {e}"))?;
    println!("created {path}");
    Ok(ExitCode::SUCCESS)
}
