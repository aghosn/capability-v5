# Designing atomic updates


## Goal

The capability engine is meant to serve as a trusted state machine on multi-core systems such as a security monitor running in root mode and isolating non-root domains.
This is described in the paper.

Its capability based operations are atomic.
This implies that there is a need for cross core synchronization, blocking concurrent operations so that we avoid inconsistencies in the capability state.

A challenge in the implementation is to design the library such that in can execute in different environments, which we call Platforms.
Platforms include running it within a monitor, as part of the unit tests, or in the CLI tool for example.
Depending on the platform, we might require different synchronization mechanisms (e.g., the monitor Platform will rely on spinlocks as it runs baremetal without any OS).

## What we need

There are two main tasks that are tightly intertwined.
We need to design an abstraction of a state that captures the fact that we run on multiple cores, and that a domain is running on one or multiple cores.

The second is that we need the update subsystem in the library to make changes to the capability state atomic across cores.
For this, it needs a few primitives that will be platform specific:
1. Preempt another core
If an update affects a domain running on a another core, the core must be preempted before the final state of the capabilities is finalized after the operation.
This includes, for example, a domain running on 2 cores and being revoked. In such a case, both cores need to go back to the appropriate parent.
Another example is a core running one domain and accepting a capability sent by another. In such a case, the memory transfer between the two domains must appear atomic. The same applies when it is rejected.

2. Updates need to be processed as part of the capability operations
The capability operations must either succeed (updates have been applied), or fail (leaves the capability state unchanged).

3. Blocking competing operations

The semantics of the capabilities should be atomic. There should not be interleaving of conflicting operations. This should be handled within the capability library, leveraging the fact that we use arc.

# Task 

Can you re-design the update mechanim and the Platform abstraction in the code such that it satisfies the requirements? Find the other possible conflicts not described here, document and address them.

Then, create a platform for tests (including multi threaded ones) and port the CLI to this new implementation by creating a special Platform for it. This might require to make deep modifications in how the CLI current handles its state.
