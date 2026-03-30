# Skill: Agent Workflow — Session Hygiene

## When to Use

**Always.** This skill applies to every agent session in this repository, regardless of
what you are working on. Load it alongside any task-specific skill.

---

## Startup Ritual (do this before any code change)

1. **Read `CONTEXT.md`** at the repo root. It contains the axioms (A1–A11) and
   authoritative design decisions. Never violate an axiom. If a task seems to require
   it, stop and ask.

2. **Read `todo.md`** at the repo root. Understand:
   - The "Current Status" section — what phase is active, what is in progress.
   - The last known debugging state (trace sequence, last hang point, hypothesis).
   - Open phases relevant to your task.

3. **Read any task-specific skills** from `skills/` that apply to your work:
   - Working on `capa-engine/`: read `skills/working-on-capability-engine.md`
   - Booting / testing inside dom0 or capavisor: read `skills/running-inside-dom0.md`
   - Debugging dom boot: read `skills/debugging-dom-boot.md`

4. **Do not start writing code until you have read all three above.** If the task is
   purely read-only (investigation, design), you may skip step 3 but not 1 and 2.

---

## Maintaining `todo.md` During the Session

`todo.md` is the living state of the project. It is the handoff document between
sessions. Treat it as part of the code — every meaningful action must be reflected in it.

### When you start a task

Find the relevant phase item(s) in `todo.md` and mark them **in progress**:

```markdown
- [ ] **P16.6b2** — fix pvclock … ← add "(IN PROGRESS as of YYYY-MM-DD)" suffix
```

If the task is not already listed, add it under the appropriate phase before starting.

### When you complete a task

- Change `[ ]` to `[x]` and add `✅ DONE.` with a one-sentence summary of what was
  done and where the code lives. Example:

  ```markdown
  - [x] **P16.6b2** ✅ DONE. Added pvclock stub in `capavisor/src/vmexit.rs::handle_msr_write`
    so dom1 never sees an uninitialised version counter.
  ```

- Update the **Current Status** section at the top of `todo.md` to reflect the new
  milestone or progress line.

### When you are interrupted mid-task (hang, crash, or end of session)

Add or update the debugging stack note in the **Current Status** section. It must
contain enough context for the next agent to pick up immediately without reading logs.
Use this template:

```markdown
- **<Short task title> (YYYY-MM-DD, IN PROGRESS)**:
  Goal: <one sentence>

  What was tried:
  - <action> → <outcome / what it ruled out>
  - <action> → <outcome / what it ruled out>

  Current hypothesis: <working theory>

  Last known state / trace:
  ```
  <trace snippet or key observation>
  ```

  Next step: <exactly what to do next>
```

Never leave a session without this block if the task is unfinished.

---

## Documenting File Changes

Before ending any session that modified files, add or update a "Changes this session"
block in the **Current Status** section of `todo.md`:

```markdown
  Files modified this session:
  - `path/to/file.rs` — what changed and why
  - `path/to/script.sh` — what changed and why
  Files created:
  - `path/to/new_file.md` — purpose
```

This is not optional. The next agent (or the user reviewing the diff) needs to know
what changed and why without reading git diff output.

---

## Build and Test Hygiene

- **Never leave the repo with a broken build.** If you break something while
  investigating and cannot fix it in the session, revert your changes and document the
  approach in the debugging stack note instead.
- After any change to `capa-engine/`, run `cargo test` from `capa-engine/` and confirm it passes.
- After any change to `capa-cli/`, run `cargo build --release` from `capa-cli/`.
- After any change to `themis/`, run `cargo build-bins` and note the result.
- If a build fails, record the error in the debugging stack note before stopping.

---

## End-of-Session Checklist

Before finishing, verify each item:

- [ ] `todo.md` **Current Status** reflects what was done this session.
- [ ] Every completed phase item is marked `[x] ✅ DONE.` with a summary.
- [ ] Every in-progress item has a debugging stack note with "Next step".
- [ ] All modified files are listed with a reason.
- [ ] The repo builds (no broken compilation left behind).
- [ ] No temporary debug files left in the repo root (clean up `/tmp/out.txt`
      references, stray test binaries, etc. — but leave `/tmp/out.txt` itself if
      a boot trace is actively being analysed).

---

## Using Multiple Skills Together

Skills are plain markdown files. An agent can (and should) read several:

```
Before starting, read:
  skills/agent-workflow.md          ← always
  skills/working-on-capability-engine.md   ← when touching capa-engine/
  skills/running-inside-dom0.md     ← when running tests in dom0
  skills/debugging-dom-boot.md      ← when debugging a kernel boot hang
```

There is no magic — just read each file in turn before acting. The agent-workflow skill
takes precedence on process; task-specific skills take precedence on technical detail.

---

## What "Current Status" in `todo.md` Should Look Like

The section at the top of `todo.md` is the single most important piece of state. Keep
it accurate. A well-maintained Current Status looks like:

```markdown
## Current Status

**✅ MILESTONE: dom0 boots to login prompt on 4 CPUs.**
**🚧 IN PROGRESS: dom1 (nested Ubuntu Noble) boot under CHV on Themis.**

- <bullet per completed phase, newest first>
- ...

- **<Active debugging task> (YYYY-MM-DD, IN PROGRESS)**:
  Goal: …
  What was tried: …
  Current hypothesis: …
  Last known trace: …
  Next step: …

  Files modified this session:
  - `file.rs` — reason
```

A poorly maintained Current Status (missing in-progress notes, stale milestones, no
file list) wastes the entire next session on re-investigation. Do not let that happen.
