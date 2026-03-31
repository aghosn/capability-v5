/-
  LeanExec.Cli — Command parser and interactive REPL.

  Parses text commands into `Command` values and provides the
  main REPL loop with file-loading support.
-/
import LeanExec.Engine

namespace LeanExec

open ThemisCapa

-- ════════════════════════════════════════════════════════════════════
-- § Parsing helpers
-- ════════════════════════════════════════════════════════════════════

/-- Trim whitespace from a string (returns String). -/
private def trim (s : String) : String :=
  s.trimAscii.toString

/-- Parse a hex "0x1a2b", binary "0b1010", or decimal "42" string into a Nat. -/
def parseHex (s : String) : Option Nat :=
  let s := trim s
  if s.startsWith "0x" || s.startsWith "0X" then
    let hex := (s.drop 2).toString.toLower
    if hex.isEmpty then none
    else
      let chars := hex.toList
      chars.foldlM (init := 0) fun acc c =>
        if '0' ≤ c && c ≤ '9' then some (acc * 16 + (c.toNat - '0'.toNat))
        else if 'a' ≤ c && c ≤ 'f' then some (acc * 16 + (c.toNat - 'a'.toNat + 10))
        else none
  else if s.startsWith "0b" || s.startsWith "0B" then
    let bin := (s.drop 2).toString
    if bin.isEmpty then none
    else
      bin.toList.foldlM (init := 0) fun acc c =>
        if c == '0' then some (acc * 2)
        else if c == '1' then some (acc * 2 + 1)
        else none
  else
    s.toNat?

/-- Parse a rights string "RWX", "RW", "R", "---" etc. -/
def parseRights (s : String) : Option Rights :=
  some (parseRightsString s)

/-- Parse an API string "CREATE,SEND,CARVE" or "ALL" or "NONE". -/
def parseApi (s : String) : MonitorAPI :=
  parseApiString s

/-- Parse an attributes string "CLEAN,VITAL" or "NONE". -/
def parseAttributes (s : String) : Attributes :=
  parseAttrsString s

-- ════════════════════════════════════════════════════════════════════
-- § Command parser
-- ════════════════════════════════════════════════════════════════════

/-- Split a line into non-empty whitespace-separated tokens. -/
private def tokenize (line : String) : List String :=
  ((trim line).splitOn " ").filter (· != "")

/-- Find "at <value>" in a token list and return (remaining, gpaValue). -/
private def extractAt (tokens : List String) : List String × Option Nat :=
  let rec go (acc : List String) : List String → List String × Option Nat
    | [] => (acc.reverse, none)
    | "at" :: val :: rest =>
      match parseHex val with
      | some n => (acc.reverse ++ rest, some n)
      | none => go ("at" :: acc) (val :: rest)
    | t :: rest => go (t :: acc) rest
  go [] tokens

def parseCommand (line : String) : Option Command :=
  let tokens := tokenize line
  match tokens with
  | [] => none

  | "init" :: name :: sizeStr :: _ =>
    parseHex sizeStr |>.map (Command.init name ·)

  | "create-domain" :: parent :: name :: coresStr :: rest =>
    let apiStr := match rest with
      | api :: _ => api
      | [] => "ALL"
    parseHex coresStr |>.map (Command.createDomain parent name · apiStr)

  | "carve" :: parent :: name :: startStr :: sizeStr :: rest =>
    let rightsStr := match rest with
      | r :: _ => r
      | [] => "RWX"
    match parseHex startStr, parseHex sizeStr with
    | some start, some size => some (Command.carve parent name start size rightsStr)
    | _, _ => none

  | "alias" :: parent :: name :: startStr :: sizeStr :: rest =>
    let rightsStr := match rest with
      | r :: _ => r
      | [] => "RWX"
    match parseHex startStr, parseHex sizeStr with
    | some start, some size => some (Command.alias_ parent name start size rightsStr)
    | _, _ => none

  | "send" :: first :: second :: rest =>
    let (remaining, gpa) := extractAt rest
    let attrsStr := match remaining with
      | a :: _ => a
      | [] => "NONE"
    some (Command.send first second attrsStr gpa)

  | "seal" :: domain :: _ =>
    some (Command.seal domain)

  | "revoke" :: parent :: child :: _ =>
    some (Command.revoke parent child)

  | "switch" :: coreStr :: [] =>
    parseHex coreStr |>.map (Command.switchCmd none · none)

  | "switch" :: domain :: coreStr :: vpStr :: _ =>
    match parseHex coreStr, parseHex vpStr with
    | some core, some vp => some (Command.switchCmd (some domain) core (some vp))
    | _, _ => none

  | "interrupt" :: vecStr :: domOrCore :: rest =>
    match parseHex vecStr with
    | some vec =>
      match rest with
      | coreStr :: _ =>
        parseHex coreStr |>.map (Command.interrupt vec domOrCore ·)
      | [] =>
        match parseHex domOrCore with
        | some core => some (Command.interrupt vec "" core)
        | none => none
    | none => none

  | "list" :: _ => some Command.list

  | "view" :: domain :: _ => some (Command.view domain)

  | "enumerate-pending" :: domain :: _ =>
    some (Command.enumeratePending domain)

  | "accept-capability" :: domain :: idStr :: rest =>
    let (_, gpa) := extractAt rest
    parseHex idStr |>.map (Command.acceptCapability domain · gpa)

  | "reject-capability" :: domain :: idStr :: _ =>
    parseHex idStr |>.map (Command.rejectCapability domain ·)

  | "get-chan" :: target :: chanName :: _ =>
    some (Command.getChan target chanName)

  | "send-channel" :: chan :: receiver :: _ =>
    some (Command.sendChannel chan receiver)

  | "accept-channel" :: receiver :: idStr :: chanName :: _ =>
    parseHex idStr |>.map (Command.acceptChannel receiver · chanName)

  | "reject-channel" :: receiver :: idStr :: _ =>
    parseHex idStr |>.map (Command.rejectChannel receiver ·)

  | "register-comm" :: mem :: child :: vpStr :: _ =>
    parseHex vpStr |>.map (Command.registerComm mem child ·)

  | "set-policy" :: parent :: child :: field :: valueStr :: _ =>
    parseHex valueStr |>.map (Command.setPolicy parent child field ·)

  | "get-policy" :: parent :: child :: field :: _ =>
    some (Command.getPolicy parent child field)

  | "set-register" :: parent :: child :: vpStr :: regStr :: valStr :: _ =>
    match parseHex vpStr, parseHex regStr, parseHex valStr with
    | some vp, some reg, some val => some (Command.setRegister parent child vp reg val)
    | _, _, _ => none

  | "get-register" :: parent :: child :: vpStr :: regStr :: _ =>
    match parseHex vpStr, parseHex regStr with
    | some vp, some reg => some (Command.getRegister parent child vp reg)
    | _, _ => none

  | "attest" :: domain :: _ =>
    some (Command.attest domain)

  | "set-interrupt-policy" :: domain :: vecStr :: visStr :: _ =>
    match parseHex vecStr, parseHex visStr with
    | some vec, some vis => some (Command.setInterruptPolicy domain vec vis)
    | _, _ => none

  | "add-vp" :: parent :: child :: commMem :: vpStr :: _ =>
    parseHex vpStr |>.map (Command.addVp parent child commMem ·)

  | "help" :: _ => some Command.help

  | "reset" :: rest =>
    let numCores := match rest with
      | n :: _ => (parseHex n).getD 4
      | [] => 4
    some (Command.reset numCores)

  | _ => none

-- ════════════════════════════════════════════════════════════════════
-- § REPL — interactive read-eval-print loop
-- ════════════════════════════════════════════════════════════════════

/-- Process a single line: parse, dispatch, return output string. -/
private def processLine (stRef : IO.Ref CliState) (line : String) : IO (Option String) := do
  let trimmed := trim line
  if trimmed.isEmpty || trimmed.startsWith "#" then
    return none
  match parseCommand trimmed with
  | some cmd => do
    let result ← dispatch stRef cmd
    return some result
  | none =>
    return some s!"Unknown command: {trimmed}\nType 'help' for available commands."

/-- Load and execute commands from a file, one per line. -/
private def loadFile (stRef : IO.Ref CliState) (filename : String) : IO String := do
  let content ← try
    IO.FS.readFile ⟨filename⟩
  catch e =>
    return s!"Error loading '{filename}': {e}"
  let lines := content.splitOn "\n"
  let mut output := s!"Loading '{filename}'...\n"
  for line in lines do
    let trimmed := trim line
    if trimmed.isEmpty || trimmed.startsWith "#" then
      continue
    output := output ++ s!"capa> {trimmed}\n"
    match ← processLine stRef trimmed with
    | some result => output := output ++ result ++ "\n"
    | none => pure ()
  output := output ++ s!"Done loading '{filename}'."
  pure output

/-- The main REPL loop. -/
partial def repl : IO Unit := do
  IO.println "╔══════════════════════════════════════════════════════════════╗"
  IO.println "║  LeanExec — Executable Lean 4 model of Themis capabilities  ║"
  IO.println "║  Type 'help' for commands, 'quit' to exit.                 ║"
  IO.println "╚══════════════════════════════════════════════════════════════╝"
  IO.println ""

  let stRef ← IO.mkRef CliState.empty
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout

  let rec loop : IO Unit := do
    stdout.putStr "capa> "
    stdout.flush
    let line ← stdin.getLine
    -- EOF check
    if line.isEmpty then do
      IO.println ""
      return
    let trimmed := trim line
    -- Quit
    if trimmed == "quit" || trimmed == "exit" then
      IO.println "Goodbye."
      return
    -- Skip blank/comment
    if trimmed.isEmpty || trimmed.startsWith "#" then
      loop
      return
    -- Load file
    if trimmed.startsWith "load " then
      let filename := trim ((trimmed.drop 5).toString)
      let output ← loadFile stRef filename
      IO.println output
      loop
      return
    -- Normal command
    match parseCommand trimmed with
    | some cmd => do
      let result ← dispatch stRef cmd
      IO.println result
    | none =>
      IO.println s!"Unknown command: {trimmed}"
      IO.println "Type 'help' for available commands."
    loop
  loop

end LeanExec
