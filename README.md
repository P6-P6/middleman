# middleman

A gatekeeper that sits in front of a database. Every request is ripped up and rebuilt
from an approved menu. Nothing the requester sends ever reaches the database directly.

A requester can be an AI agent over MCP, an app, or a person at a terminal. They all go
through the same gate.

**In short:**

- **One way in.** A requester gets only the actions on its menu. Each request is checked field by field,
  then rebuilt from SQL written at startup, so nothing it sends runs as-is.
- **Sensitive data stays covered.** Every column has a sensitivity level. Columns above a requester's
  clearance are masked or never fetched.
- **People approve writes.** Writes wait for a person to say yes.
- **Everything is logged.** Every request, accepted or refused, goes into a log that refuses edits and deletes.
- **Hidden attacks are stripped.** Invisible Unicode tricks in the data are removed before the AI sees them.

This is version 1: one SQLite database, reached over MCP or the command line, with 32 tests.
Version 2 adds more kinds of data store, a network door, an approval queue and sealed values:
[P6-P6/middleman-v2](https://github.com/P6-P6/middleman-v2).

## What every request goes through

1. **Size gate.** Messages over 64 KB are dropped before anything parses them.
2. **Strict parse.** Duplicate keys, trailing garbage, broken escapes and deep nesting are refused.
3. **Menu.** The action must be on this requester's menu. Other actions are not even listed.
4. **Reason.** Every request names a reason from an approved list. It is logged.
5. **Fields.** Any field the action does not declare is refused.
6. **Inputs.** Every value must fit its typed rule exactly. Invisible and control characters are refused.
7. **Budget.** Calls and rows per minute, hour or day, counted from the audit log.
8. **Approval.** Actions marked `confirm` ask a person first. Inside Claude Code this is an MCP elicitation prompt.
9. **Rebuild.** The SQL was written at startup from the rules. Checked values are bound as parameters.
10. **Clean reply.** Withheld columns are never fetched. Masked columns are masked. Hidden characters
    are stripped. Sizes are capped. The reply opens with a notice that its contents are data, not instructions.

Every request is logged, accepted or refused. The log never stores values, and it refuses edits and deletes.
Refusal messages are fixed text and never repeat what the requester sent.

## Quick start

Build from PowerShell. The script finds the Visual Studio build tools by itself.

```powershell
.\build.ps1            # release build
.\build.ps1 test       # unit tests and attack tests
```

Try the demo:

```powershell
$m = ".\target\release\middleman.exe"
& $m demo-db examples\shop.db          # only if examples\shop.db does not exist yet
& $m check examples\shop.rules         # every requester's menu, and why things are refused

$env:MIDDLEMAN_KEY = "demo-support-agent-c880cdaf31f993b879a5d84d65c563cf"
& $m call examples\shop.rules read_customer reason=support customer_id=3
& $m call examples\shop.rules open_ticket reason=support customer_id=3 "body=Printer is on fire"
& $m log examples\shop.rules
```

Customer 3's notes contain a prompt-injection attack, partly hidden in invisible Unicode characters.
Watch the hidden part disappear and the rest come back labeled as data.

## Using it from Claude Code

This folder has a `.mcp.json` that connects Claude Code to the demo as the `support-agent` requester.
Open the folder in Claude Code and approve the `middleman` server when asked. The AI then sees four
tools. Writes like `open_ticket` show you an approval prompt first.

Rebuilding while Claude Code is running fails, because Windows locks the running program. Stop the
server with `/mcp` first.

## The rules language

One file says everything that is allowed. Indent with spaces. Lines starting with `#` are comments.
Any mistake stops the middleman from starting, with the line number.

```text
database shop.db               # the database to guard, relative to this file
audit    audit.db              # the audit log, created if missing

levels                         # sensitivity levels, 0 to 9, each with a one-word name
  0 public
  3 restricted

table customers                # every column in the real table must be labeled
  ssn  level 3
  together zip + birthdate level 2    # columns that are more sensitive together

requester billing-app
  key-sha256  <hash>           # from: middleman hash-key
  machines    any              # or a list of computer names
  clearance   2
  reasons     invoice, refund
  budget      calls 120 per minute    # calls or rows, per minute, hour or day

action read_customer
  about    Read one customer.  # shown to the AI
  kind     read                # read, insert or update
  table    customers
  input    customer_id: integer 1..999999
  where    id = customer_id    # operators: = < <= > >=
  returns  first_name, ssn
  mask     ssn last 4          # or: mask ssn all
  order    id asc              # optional
  rows     1                   # most rows returned, or changed by an update
  bytes    16384               # optional reply size cap
  timeout  2000                # optional, milliseconds
  reasons  invoice, audit
  confirm  no                  # default: no for reads, yes for writes
```

Trailing comments like the ones above are for this README only. In a real file, comments go on their own lines.

Input types:

| Type | Example | Accepts |
|---|---|---|
| integer | `integer 1..999999` | A whole number in range. Never text, never decimals. |
| text | `text name max 40` | Text in one character set, up to a length. |
| choice | `choice open, closed` | One of the listed words, exactly. |
| date | `date` | A real date written YYYY-MM-DD. |

Character sets for text: `digits`, `alnum`, `name`, `email`, `phone`, `code` and `line`.
Only `name` and `line` accept letters outside ASCII.

How levels decide what a requester sees:

- A column at or below the requester's clearance is shown.
- A column above it is masked if the action has a `mask` for it, and withheld otherwise.
- If a `together` group would be fully visible above clearance, only its first column stays.
- An action that filters or sorts by a column needs clearance for that column.
- An action that writes a column needs clearance for that column.
- An update must have a `where`, so it can never change every row.

## What version 1 does not do

- **Know who suggested a value.** An MCP server sees requests, not the AI's conversation.
  It can't tell whether a value came from the user or from a web page the AI read.
  Approval prompts cover risky writes until version 2 tracks where values come from.
- **Stop an AI from being influenced by what it reads.** Visible text in the data still reaches the AI.
  The notice helps, but the menu and permissions are the real protection.
- **Stop an AI that can open the database file itself.** Claude Code has its own file and shell tools.
  Real isolation needs the database under a separate Windows account that only the middleman can use.
- **Judge intent.** An allowed request made for a bad reason still goes through.
- **Guard anything but SQLite.** Files, web requests and other databases need their own adapters.

## Ideas for version 2

- Run as a network service with certificate-based machine identity and IP tags.
- Track where every value came from by running the AI's loop, as Google DeepMind's CaMeL does.
- Labels that follow data, so level 3 data can never be written into a level 1 place.
- More adapters: files, HTTP APIs, Postgres.
- Fuzz the parsers continuously with cargo-fuzz.

## License

Copyright (c) 2026 P6-P6. Free to use under either of two licenses, whichever fits you:

- [PolyForm Noncommercial 1.0.0](LICENSE-NONCOMMERCIAL.md): personal use, hobby projects, research,
  schools, charities and government.
- [PolyForm Small Business 1.0.0](LICENSE-SMALL-BUSINESS.md): companies with fewer than 100 people and
  under $1,000,000 (2019 dollars) in revenue last year.

Larger companies need a separate license. Ask through [GitHub](https://github.com/P6-P6).
