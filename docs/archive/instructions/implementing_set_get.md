# Implementing set and get

We need to implement set and get and more generally restrict modifications of the domain after sealing.

The [paper](2026/eurosp2026.pdf) describes this behavior where policies cannot be modified after sealing, while registers can be queried or overwritten by the domain holding the capability for the target child domain if the policies allow it.
Ideally, I'd like a bitmap of size platform specific to say how many "registers" there are for the domain.
Before the domain is sealed, set should allow to set both the registers and the policies (e.g., this bitmap but also what we use for interrupt policies or other policies such as editing the Monitor API or cores for the domain).

here we run into a small issue which is that we so far allocate VPs at seal time.
We should do that earlier since the register content is per VP (but the bitmap policy is domain-wide). That means for example that if the policy bitmap says the parent can read/write register 1, that is the case on all the domain's VP. 

# Set

Set is therefore extremely parametric:

Set POLICY IDENTIFIER Value
* Can be used to modify domain-wide policies in a child BEFORE IT IS SEALED.

SET REGISTER VP IDENTIFIER Value
* Can be used to modify a regiister content for a child.

For the first case, everything happens within the capability engine.
For the second case, validation happens in the capability engine but ends somewhere in the platform that is in charge of maintaining register state per VP. 


Maybe to simplify things a bit as a first stage, let's assume core and number of VPs is set at domain creation and cannot be modified. 

# Get 
For get operations, a Get on a policy always succeeds.
A get on a register content is subjected to another bitmap, similar to set.


# Get and Set on interrupts

We want to have a behavior that's custom depending on interrupts.
Set and Get should work as above BUT their bitmaps should be the one specified in interrupt policies if the domain is interrupted or suspended.

Maybe a good approach that's generic would be to consider the case where the VP is available as a synthetic interrupt with vector number "-1" or another value that's not used.

What do you think?


# Task to perform

Suggest an implementation, let's validate the plan and start working on it.
