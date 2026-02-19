### Title
Permission Bypass in SetCandidateAdmin via InitialPubkeyMap Resolution Inconsistency

### Summary
The `SetCandidateAdmin()` function contains a critical state inconsistency where the pubkey resolution via `InitialPubkeyMap` is used for admin storage but not for permission validation. When a candidate pubkey has been replaced and the initial pubkey has no admin set (possible with legacy contract state), an attacker controlling the replacement pubkey's private key can claim admin authority over the original candidate, enabling fund theft and unauthorized governance actions.

### Finding Description

The vulnerability exists in the `SetCandidateAdmin()` function where two different pubkey values are used inconsistently: [1](#0-0) 

At line 26, `input.Pubkey` is resolved to its initial pubkey via the `InitialPubkeyMap`. This mapping is populated during pubkey replacements to track the chain of replacements back to the original pubkey. [2](#0-1) 

However, the permission check for setting an admin for the first time uses the INPUT pubkey, not the RESOLVED pubkey: [3](#0-2) 

This inconsistency means that while the admin is stored and checked under the resolved initial pubkey (line 29, 42), the permission validation checks if the sender controls the INPUT pubkey (line 32). The comment on line 31 explicitly acknowledges that admins may not be set "due to old contract code", confirming that legacy state with unmapped initial pubkeys can exist. [4](#0-3) 

The correct behavior is confirmed by other functions like `QuitElection` which properly uses the resolved initial pubkey for admin checks: [5](#0-4) 

And the view function `GetCandidateAdmin` which always resolves through the mapping: [6](#0-5) 

### Impact Explanation

An attacker who controls the private key of a replacement pubkey can gain unauthorized admin authority over the original candidate when the initial pubkey has no admin set. This grants the attacker:

1. **Fund Theft**: Ability to call `QuitElection()` to unlock and steal the `ElectionContractConstants.LockTokenForElection` tokens locked during candidate announcement. [7](#0-6) 

2. **Candidate Control**: Authority to replace the candidate's pubkey again via `ReplaceCandidatePubkey()`, potentially creating further exploitation chains. [8](#0-7) 

3. **Persistent Access**: Once the attacker sets themselves as admin, they maintain control over all future administrative actions for that candidate lineage.

The severity is HIGH because it enables unauthorized asset theft from locked candidate deposits and breaks the authorization invariant for candidate management.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Control of private key for a replacement pubkey (pubkey B where `InitialPubkeyMap[B] = A`)
- Transaction signing capability to call `SetCandidateAdmin()`

**Feasible Preconditions:**
The vulnerability requires legacy contract state where:
1. A candidate pubkey was replaced creating an `InitialPubkeyMap` entry
2. The original (initial) pubkey has no admin set (`State.CandidateAdmins[A] == null`)

This condition is explicitly acknowledged in the code comment "due to old contract code", indicating it exists in deployed contracts. Such state could arise from:
- Contract upgrades where admins were added as a feature later
- Initial miners from genesis that never had admins set
- Early pubkey replacements performed under different logic

**Execution Practicality:**
The attack is straightforward once preconditions are met:
1. Attacker identifies candidates with replacement mappings but no admin
2. Attacker controls or obtains the replacement pubkey's private key
3. Single transaction to `SetCandidateAdmin()` claims admin authority
4. Follow-up transaction to `QuitElection()` steals locked funds

**Economic Rationality:**
Attack cost is minimal (gas fees only), while potential gain includes locked candidate deposits. The likelihood is MEDIUM due to dependency on legacy state existence and attacker's key control.

### Recommendation

**Immediate Fix:**
Change the permission check on line 32 to use the resolved `pubkey` variable instead of `input.Pubkey`:

```csharp
// Change from:
Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
    "No permission.");

// To:
Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey)),
    "No permission.");
```

This ensures the permission check validates control of the INITIAL pubkey, consistent with how admin is stored and checked throughout the contract.

**Additional Safeguards:**
1. Add invariant check: If `InitialPubkeyMap[input.Pubkey]` exists (i.e., this is a replacement pubkey), require that an admin MUST already be set for the initial pubkey before allowing first-time admin setting via the replacement pubkey.

2. State migration: For existing contracts, run a governance-approved migration to set admins for all candidates/initial miners that currently have null admins, closing the vulnerability for legacy state.

3. Add test cases covering:
   - Setting admin via replacement pubkey when initial pubkey has no admin
   - Setting admin via replacement pubkey when initial pubkey has admin
   - Attempting to set admin from wrong pubkey in replacement chain

### Proof of Concept

**Initial State:**
- Initial miner with pubkey "A" exists from genesis, no admin set: `State.CandidateAdmins["A"] == null`
- Via governance, pubkey "A" was replaced with "B": `State.InitialPubkeyMap["B"] = "A"`
- Attacker controls private key for pubkey "B"
- Pubkey "B" is current candidate: `State.CandidateInformationMap["B"].IsCurrentCandidate == true`

**Attack Steps:**
1. Attacker creates transaction signed with private key of pubkey "B"
2. Calls `SetCandidateAdmin(input.Pubkey = "B", input.Admin = attackerAddress)`
3. Execution path:
   - Line 21: `IsCurrentCandidateOrInitialMiner("B")` → TRUE (passes)
   - Line 23: `!IsPubkeyBanned("B")` → TRUE (passes)
   - Line 26: `pubkey = InitialPubkeyMap["B"] = "A"`
   - Line 27-28: Sender is not Parliament, proceeds to line 29
   - Line 29: `State.CandidateAdmins["A"] == null` → TRUE (no admin set)
   - Line 32: `Context.Sender == Address.FromPublicKey("B")` → TRUE (attacker controls B)
   - Line 42: Sets `State.CandidateAdmins["A"] = attackerAddress`
4. Attacker now controls admin for candidate "A" (and by extension "B")
5. Attacker calls `QuitElection("B")` to unlock and steal locked tokens

**Expected vs Actual:**
- **Expected**: Only the entity controlling pubkey "A"'s private key should be able to set the initial admin
- **Actual**: Any entity controlling a replacement pubkey "B" can set the admin if it was never set for "A"

**Success Condition:**
After step 3, `GetCandidateAdmin("A")` and `GetCandidateAdmin("B")` both return `attackerAddress`, and attacker can execute privileged admin operations including fund withdrawal.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L26-26)
```csharp
        var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L29-33)
```csharp
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L42-42)
```csharp
        State.CandidateAdmins[pubkey] = input.Admin;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-249)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L180-181)
```csharp
        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L288-289)
```csharp
        var initialPubkey = State.InitialPubkeyMap[oldPubkey] ?? oldPubkey;
        State.InitialPubkeyMap[newPubkey] = initialPubkey;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L411-414)
```csharp
    public override Address GetCandidateAdmin(StringValue input)
    {
        return State.CandidateAdmins[State.InitialPubkeyMap[input.Value] ?? input.Value];
    }
```
