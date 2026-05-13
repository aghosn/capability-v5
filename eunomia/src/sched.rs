//! Cooperative round-robin scheduler with context switching.
//!
//! Tasks are spawned with `spawn()` and voluntarily yield via
//! `yield_now()`.  Each task gets its own stack (heap-allocated).
//! When a task's function returns, it is removed from the run queue.
//!
//! No preemption — timer interrupts are not used for scheduling.

use alloc::collections::VecDeque;
use alloc::vec;
use core::arch::naked_asm;

/// Per-task stack size: 16 KiB.
const TASK_STACK_SIZE: usize = 16 * 1024;

/// Saved CPU context for cooperative switching.
///
/// Layout must match the push/pop order in `switch_context`.
#[repr(C)]
struct Context {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    rsp: u64,
}

impl Context {
    const fn empty() -> Self {
        Self { r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0, rsp: 0 }
    }
}

/// A schedulable task.
struct Task {
    name: &'static str,
    ctx: Context,
    #[allow(dead_code)]
    stack: alloc::vec::Vec<u8>,
    finished: bool,
}

/// Global scheduler state.
static mut SCHEDULER: Option<Scheduler> = None;

/// # Safety
/// Single-threaded access only (cooperative scheduling, no preemption).
fn sched() -> &'static mut Scheduler {
    unsafe {
        (*(&raw mut SCHEDULER)).as_mut().expect("scheduler not initialised")
    }
}

struct Scheduler {
    tasks: VecDeque<usize>,
    task_pool: alloc::vec::Vec<Task>,
    current: usize, // index into task_pool (0 = idle/main)
    idle_ctx: Context,
}

/// Initialise the scheduler.  Must be called before `spawn` or `run`.
pub fn init() {
    unsafe {
        *(&raw mut SCHEDULER) = Some(Scheduler {
            tasks: VecDeque::new(),
            task_pool: alloc::vec::Vec::new(),
            current: 0,
            idle_ctx: Context::empty(),
        });
    }
}

/// Spawn a new task.  The task will run when `run()` is called.
pub fn spawn(name: &'static str, entry: fn()) {
    let sched = sched();

    // Allocate a stack (grows downward, so SP starts at the top).
    let stack = vec![0u8; TASK_STACK_SIZE];
    let stack_top = stack.as_ptr() as usize + TASK_STACK_SIZE;

    // Align stack to 16 bytes.
    let sp = stack_top & !0xF;

    // Prepare the initial stack frame so that switch_context "returns"
    // into task_entry, which calls the actual function and then marks
    // the task as finished.
    //
    // switch_context pops: rbx, rbp, r12, r13, r14, r15, then ret.
    // We push these in reverse order (since stack grows down):
    //   [sp - 8]  = return address (task_trampoline)
    //   [sp - 16] = rbx  (we store `entry` here for the trampoline)
    //   [sp - 24] = rbp  = 0
    //   [sp - 32] = r12  = 0
    //   [sp - 40] = r13  = 0
    //   [sp - 48] = r14  = 0
    //   [sp - 56] = r15  = 0
    let frame_sp = sp - 7 * 8;
    unsafe {
        let frame = frame_sp as *mut u64;
        *frame.add(0) = 0;                             // r15
        *frame.add(1) = 0;                             // r14
        *frame.add(2) = 0;                             // r13
        *frame.add(3) = 0;                             // r12
        *frame.add(4) = 0;                             // rbp
        *frame.add(5) = entry as *const () as u64;     // rbx = entry fn
        *frame.add(6) = task_trampoline as *const () as u64; // return addr
    }

    let ctx = Context {
        rsp: frame_sp as u64,
        rbx: entry as *const () as u64,
        rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0,
    };

    let id = sched.task_pool.len();
    sched.task_pool.push(Task {
        name,
        ctx,
        stack,
        finished: false,
    });
    sched.tasks.push_back(id);
}

/// Run all spawned tasks to completion.  Returns when all tasks finish.
pub fn run() {
    let sched = sched();

    while !sched.tasks.is_empty() {
        if let Some(&next_id) = sched.tasks.front() {
            sched.current = next_id;
            let old_ctx = &raw mut sched.idle_ctx;
            let new_ctx = &raw const sched.task_pool[next_id].ctx;
            unsafe { switch_context(old_ctx, new_ctx); }

            // Back from switch — check if current task finished.
            if sched.task_pool[next_id].finished {
                sched.tasks.pop_front();
            }
        }
    }
    sched.current = 0;
}

/// Yield the current task.  Cooperative switch to the next task.
pub fn yield_now() {
    let sched = sched();

    if sched.tasks.len() <= 1 {
        return; // No other task to switch to.
    }

    // Rotate: move current to back of queue, switch to front.
    let cur_id = sched.current;
    sched.tasks.pop_front();
    sched.tasks.push_back(cur_id);

    let next_id = *sched.tasks.front().unwrap();
    sched.current = next_id;

    let old_ctx = &raw mut sched.task_pool[cur_id].ctx;
    let new_ctx = &raw const sched.task_pool[next_id].ctx;
    unsafe { switch_context(old_ctx, new_ctx); }
}

/// Returns the name of the currently running task.
pub fn current_name() -> &'static str {
    let sched = sched();
    if sched.current == 0 {
        "idle"
    } else {
        sched.task_pool[sched.current].name
    }
}

// ── Trampoline and context switch ──────────────────────────────────────── //

/// Entry point for new tasks.  RBX holds the actual entry function pointer.
///
/// After the task function returns, we mark it finished and switch back
/// to the idle context (which is inside `run()`).
#[unsafe(naked)]
extern "C" fn task_trampoline() {
    naked_asm!(
        "call rbx",          // call the task function (ptr in rbx)
        "call {finished}",   // mark task as finished + switch to idle
        "ud2",               // should never reach here
        finished = sym task_finished,
    );
}

/// Called when a task returns.  Marks it finished and switches to idle.
extern "C" fn task_finished() {
    let sched = sched();
    let cur_id = sched.current;
    sched.task_pool[cur_id].finished = true;

    // Switch back to the idle context (inside `run()`).
    let old_ctx = &raw mut sched.task_pool[cur_id].ctx;
    let new_ctx = &raw const sched.idle_ctx;
    unsafe { switch_context(old_ctx, new_ctx); }
}

/// Low-level cooperative context switch.
///
/// Saves callee-saved registers + RSP to `old`, loads from `new`.
///
/// # Safety
/// Both pointers must point to valid `Context` structs.
#[unsafe(naked)]
unsafe extern "C" fn switch_context(_old: *mut Context, _new: *const Context) {
    naked_asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi + 48], rsp",
        "mov rsp, [rsi + 48]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
    );
}
