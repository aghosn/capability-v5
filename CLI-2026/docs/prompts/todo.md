I tried the interface, it's great but it's missing a few things and there are errors.
Fix the CLI and the 2026 capabilities implementation accordingly.

1. It seems to not be possible to revoke a domain.
Revoke should also work on a domain.
It revokes the domain, its children domains, as well as all the capabilities they own.
It is a cascading effect.
I tried it in problem_revoke.rs and after revocation dom1 was still there despite its capability being vital and being revoked.

2. The interface asks to supply the handle when sending.
The local handle should not be chosen by the code, they should be maintained and picked automatically from inside the receiving domain.

3. The handles, attributes, owners, and children are not reported in the CLI for memory region capabilities.
If you go back to the pdf paper in 2026/ folder, we say that these information should appear in the attestation (and also in the output of the list command).

4. Implement a "current domain" that is the result of the switch and implictly set which domain is current the active one. Even better if in the init we can specify how many cores are available and do the switch on a given core, e.g., switch dom1 2 to switch to dom1 on core 2. The list command should show the active domain on each core.

5. The interrupt command I ask is missing. It should deliver interrupt on a core: interrupt 55 2 delivers interrupt vector 55 to core 2 and triggers the interrupt routing on that core.
