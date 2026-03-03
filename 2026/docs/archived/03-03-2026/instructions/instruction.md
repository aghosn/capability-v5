The current implementation is incomplete and lacks end-to-end test cases.
I want you to extend/improve the implementation as follows:

0. Processing updates
1. Compact the implementation
2. Support end-to-end test cases that model a real deployment
3. Add support for summary of address space per domain.
4. Additional comments

# Processing updates

Right now the logic to process updates is missing.
We should have it. The goal is an instance of the monitor running with the capabilities, each core (you simulate that with threads in tests) should track the current domain running and when updates are created there should be a correct mechanism to signal the other cores that need to process the update.

For example, if one core is running and performs a carve and a send, then the domain that lost this acccess to a region and might be running on another core needs to be preempted so it can do the platform specific update as described in the paper.

# Compact implementation

A lot of the implementation right now relies on booleans when they could be implemented with bitmaps instead to reduce the space we consume at runtime.
Tests should be updated accordingly.

One such example is the monitor API permission in domains.


# Support end-to-end test cases that model a real deployment

The goal of the project is to have a "verified state machine" for resource allocation that guarantee some properties such as isolation, exclusive memory, etc.

I'd like you to write test cases that include:

A confidential VM isolated from the host with an exclusive region for its own memory and a shared (aliased) one for virtio drivers.

An enclave inside a confidential VM. 

A sandbox inside a confidential VM (so a child domain with aliased memory).

Two CVMs that communicate with private shared memory (a region for which only the two VMs have a capability).

I also want attestations for all deployments, with expected string for the attestation of each domain.

Ideally, the test would run multi-threaded, simulate domains running on multiple cores and attempting to create the domains etc.
The updates should be checked too, the accessible memory based on capabilities should be checked/asserted as well in the tests, and revocation should ensure that we always go back to the correct state. 

# Add support for summary of address space per domain

I want to visualize the address space of a domain, i.e., something derived from its memory capabilities that tells me what regions are accessible and with which access rights.
There are some examples in the 2025 folder you can draw inspiration from.
Ideally you'd write tests that show this. 


# Additional comments

-1. Remove the remapped logic
I think we can ignore the memory remapping for the moment.
We will implement this in a separate layer I think that would be cleaner and simplify the code.

0. You didn't simplify the booleans into bitmaps in the rest of the repository.
The goal is to minimize space for datastructures whenever possible. We still have booleans in the memory.rs for example that could be optimized as bitmaps. All the code should be updated consequently. And remember to move all unit tests in tests/, do not keep them in src/

1. Changing the API

Would it make sense to change the API slightly so that we would do capa.alias(access) rather than the current Capability::alias_child(&root) etc?

How would this work with local handles? Would it still work with the arc needed for parent ref?

The same applies to all other capability based operations.
Consider if it's doable, an improvement, and if so do it.
Also I don't know why you take the owner as an argument for alias and carve, the owner of the child is the same as the owner of the parent on which we call the operation.

2. In the example in main, you never send the carve to the child.

You do not seem to test the workflow:

create child
create memory regions (alias for shared, carved for exclusive)
send the capabilities to the child
seal the child.

Show the attestation
Do some scheduling (switches and interrupts to verify everything works properly).

Revoke the child from the parent to delete the children and regain the capabilities.
This should yield back the original state of the parent before the carves, aliases, and creating the child.


3. How do updates work? They need to be processed right? and it needs to be atomic, i.e., they cannot allow other capability operations to proceed until the full list of updates has been processed otherwise we could observe inconsistent state right? Fix the code if needed. 


4. Safety of memory allocation.
We do know in advance what we need to allocate right? Is there anyway we could check that the allocator has enough memory before an operation to satisfy its allocations?

5. There's a mistake in the code for revoke
It needs to compute whether regions are re-enabled in the parent address space after a revoke.
This is the case if some regions were derived from the parent capa, sent to a child (creating a change in the address space of the parent). The revoke of the child domain or its region capa will re-enable access in the owner of the parent. 

For example:

Dom0 has region1 capa 0x0 0x2000
It carves it at 0x100 to create region2 [0x1000, 0x2000)
sends region2 to the its child Dom1.
At this point Dom0 looses access to region2's memory.

Later, if Dom0 uses region1 to revoke region2 or if it revokes Dom1, region1 will regain access to [0x1000, 0x2000) (because there's no carve subtree anymore) and ideally this should be detected in revoke and trigger updates.

6. Domains do not track capabilities they own?
This is bad in the current design. We should be able to track what capabilities a particular domain has. It is useful even for revocation 
This for example is a problem and shows you do not handle updates correctly.
Imagine the following case:

Dom1 has r1 and r2
r1 = carve [0x0. 0x2000)
r2 = alias [0x0, 0x2000)
with r2 a child of r1

if we do a carve on r2, this will not change dom1's access rights to [0x, 0x2000) because it has another capability, r1, that covers that space.
More generally the logic for updates is quite complicated and requires knowledge of the domain's capabilities to understand if the domain loses or gains (e.g., being the recipient of a send) accesses.
I guess the easiest way is to compute the view before the operation from the capability and compute the view after for each domain involved and that tells you what the update is supposed to be.
Ideally, we should be able also in most cases to optimize the code to avoid having to compute the full view and instead derive what the changes are. 

7. Interrupt routing

The implementation seems wrong. It should waalk the tree upwards to find which domain to deliver it to and switch to that domain. along the path it should mark that the same interrupt must be delivered to all domain that have a deliver policy for this interrupt vector.
What will happen next is that when the parent that handled it decides to switch again to its child, we will have to check if there's a pending interrupt and if so resume "inject it" as a return value in the child. Let take the following example

dom0 has deliver for interrupt 6.
dom1 has report for interrupt 6
dom2 has not report
dom 3 has not report.

dom0 switch to dom1
    dom1 switch to dom2
        dom2 switch to dom3
            Interrupt 6 received by dom3

We walk the tree until we reach dom0.
We switch on this core back to the correct Vp context on dom0.
It appears as a return from dom1 with exit reason saying it was interrupt 6.

dom0 switches back to dom1
Dom1 resumes execution with the correct Vp context and it looks like a return from dom2 with exit reason saying it was interrupt 6 received by dom2.

dom1 decides to switch back to dom2.
dom2 has no visibility so it gets skipped and dom3 is the one that's actually scheduled (we resume the correct Vp context which was the one that received the interrupt).

Does this make sense?

8.  I also asked you if you could generate a CLI applet that uses the capability library and provides a simulator environment to play with capabilities.
It would be great if by defautl we start with the root domain and some large (e.g., 10GB) memory region. Then from the CLI we can perform capability operations (enumerate to see our local indices for the capabilities, call CARVE or ALIAS on some capabilities, create children and configure them etc, if we could have auto-complete or suggestions in the CLI that would be awesome). 
It should allow to switch on a given core to another domain etc. 
Basically a fully functional simulator that mimics a monitor providing the capability operations and the CLI is a client. If it could be parametrised such that we can specify the number of cores available when we start the CLI it'd be great. 
If you could add two more operations in the CLI, READ and WRITE (or even EXEC) that take an address and check whether according to the current domain's capabilities the operation succeeds or not, even better.
Also add another command in the CLI to deliver an interrupt e.g., INT NB CORE that allows to trigger the interrupt NB on core CORE and prints what happens then (which domain gets scheduled). 


9. There's a problem with attributes

You put attributes in the memory but the problem is that you overwrite them when sending with different ones to another domain. You store the attributes in the region when actually it'd be better if they were stored with the ownership of the capability instead. No?
