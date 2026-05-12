# Cleaning docs

before we further extend the code with new features, we need comprehensive documentation.

Most of what is available in 2026/docs/ is stale and should be removed.
The readme in there is stale as well.

I would like the following structure:

Readme.md:

    1. General description: Not too long, explain the capability engine's goals and design.
    2. Source code layout: what files are here.
    3. Build and test infrastructure: How to build, run the tests, loom, coverage.

docs/:

In the docs folder I would like the following documents

readme.md: 
    1. this acts as an overview of the design documents and a map to the subcontent.

docs/capabilities:
This subfolder contains documentation on capability semantics.
It should have:
    1. capability derivation trees: description of capability derivation tree
    2. API: general API operations on capabilities.
    3. Memory Region capability: describe the semantics for memory region capabilities
    4. Domain capabilitiy: semantics for domain capabilities

For  3 and 4, have a section with allowed operations, and examples for each operation (success and failing). 
For 2, show a flow of operations. You can use high-level language (similar to the cli commands) rather than the actual code to describe these operations.

docs/implementation

Here we will talk about the implemenation.
    1. Overview (as readme.md): description of the parts, the capabilities, updates, platform, sync module and how they fit together.
    1. Capabilities: documentation about actual implementation of capabilities
    2. Concurrency: how concurrency is handled and what's allowed.
    3. Updates: describe the updates
    4. Platform: what it is and how to create one. what's the API and reference the example implementations we have for the tests, loom and for CLI.


What do you think about this plan? Make suggestions and then we can start generating the content.
Move the old files including the instructions in docs/archived/03-03-2026/.
