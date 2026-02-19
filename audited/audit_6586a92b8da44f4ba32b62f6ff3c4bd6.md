### Title
Missing Null Check in PerformReplacement() for ManagedCandidatePubkeysMap Update

### Summary
The `PerformReplacement()` function in `ElectionContract_Maintainence.cs` does not defensively handle null values when accessing `ManagedCandidatePubkeysMap[Context.Sender]`, unlike other methods in the contract that consistently use the `?? new PubkeyList()` pattern. This inconsistency could cause transaction failures with NullReferenceException in edge cases such as incomplete contract upgrades or state migration scenarios.

### Finding Description
The `PerformReplacement()` function directly accesses `State.ManagedCandidatePubkeysMap[Context.Sender]` without null-checking: [1](#0-0) 

This contrasts with the defensive programming pattern used consistently throughout the contract. For example, in `SetCandidateAdmin()`: [2](#0-1) 

And: [3](#0-2) 

Similarly, in `AnnounceElection()`: [4](#0-3) 

And in `AnnounceElectionFor()`: [5](#0-4) 

All these methods use the `?? new PubkeyList()` pattern to safely handle null cases, but `PerformReplacement()` does not.

The `ManagedCandidatePubkeysMap` state is defined as: [6](#0-5) 

If `State.ManagedCandidatePubkeysMap[Context.Sender]` returns null, calling `.Value.Remove()` and `.Value.Add()` on the null object will throw a NullReferenceException, causing the transaction to fail.

### Impact Explanation
**Operational Impact:**
- A candidate admin's attempt to replace a pubkey via `ReplaceCandidatePubkey()` would fail with a NullReferenceException
- The pubkey replacement operation would be blocked until the state inconsistency is resolved
- No fund loss or unauthorized access occurs, but legitimate operations are disrupted

The entry point is: [7](#0-6) 

**Affected Users:**
- Candidate admins attempting to replace pubkeys in edge case scenarios
- Particularly affects scenarios following contract upgrades or incomplete state migrations

**Severity Justification:**
Low severity because:
1. No fund theft, inflation, or authorization bypass
2. Only causes transaction failures, not state corruption
3. All normal operational flows properly initialize the map
4. Requires edge case conditions (e.g., incomplete contract upgrade/migration)

### Likelihood Explanation
**Low Likelihood:**

Under normal operations, the likelihood is very low because all standard code paths properly initialize `ManagedCandidatePubkeysMap`:
- When candidates announce election, their admin's entry is initialized
- When admins are set or changed via `SetCandidateAdmin()`, both old and new admin entries are properly handled

**Edge Case Scenarios:**
1. **Contract Upgrade**: If the Election contract is upgraded and existing candidate admins exist in the `CandidateAdmins` state mapping but the new `ManagedCandidatePubkeysMap` state isn't properly migrated, an admin could pass the permission check but hit the null reference error.

2. **State Inconsistency**: Any scenario where an admin address exists in `CandidateAdmins` (returned by `GetCandidateAdmin()`) but has no corresponding entry in `ManagedCandidatePubkeysMap`.

The permission check that must pass before reaching the vulnerable code: [8](#0-7) 

Then `PerformReplacement()` is called: [9](#0-8) 

### Recommendation
Apply the same defensive null-handling pattern used throughout the contract:

**Code-level mitigation:**
In `PerformReplacement()`, change line 323 from:
```csharp
var managedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender];
```

To:
```csharp
var managedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender] ?? new PubkeyList();
```

**Invariant to add:**
Ensure that whenever a `CandidateAdmin` entry exists, there is a corresponding `ManagedCandidatePubkeysMap` entry for that admin address.

**Test cases to add:**
1. Test pubkey replacement after contract upgrade/migration scenarios
2. Test pubkey replacement when admin is set through various paths
3. Verify defensive handling of null/empty `ManagedCandidatePubkeysMap` entries

### Proof of Concept
**Required Initial State:**
1. A candidate exists with an admin set in `CandidateAdmins` state
2. The admin's address does NOT have an entry in `ManagedCandidatePubkeysMap` (simulating incomplete migration or state inconsistency)

**Transaction Steps:**
1. Admin calls `ReplaceCandidatePubkey()` with valid `OldPubkey` and `NewPubkey`
2. Permission check at line 181 passes (admin exists in `CandidateAdmins`)
3. `PerformReplacement()` is called at line 184
4. At line 323, `State.ManagedCandidatePubkeysMap[Context.Sender]` returns null
5. At line 324, `managedPubkeys.Value.Remove()` throws NullReferenceException

**Expected Result:**
Transaction completes successfully with pubkey replacement

**Actual Result:**
Transaction fails with NullReferenceException: "Object reference not set to an instance of an object"

**Success Condition:**
With the recommended fix (adding `?? new PubkeyList()`), the transaction would succeed even when the map entry is null, maintaining consistency with the defensive programming pattern used elsewhere in the contract.

### Notes
This is a **code quality and defensive programming issue** rather than a critical security vulnerability. While all normal operational flows properly initialize the `ManagedCandidatePubkeysMap`, the lack of defensive null-checking creates an inconsistency with the rest of the codebase and could cause unexpected failures in edge cases. The fix is straightforward and aligns with the established pattern used in other methods like `SetCandidateAdmin()`, `AnnounceElection()`, and `AnnounceElectionFor()`.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-257)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);

        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));

        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }

        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }

        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }

        //     For CandidateVotes and CandidateInformation, just replace value of origin pubkey.
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }

        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }

        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;

        ReplaceCandidateProfitsReceiver(input.OldPubkey, input.NewPubkey);
        
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L323-326)
```csharp
        var managedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender];
        managedPubkeys.Value.Remove(oldPubkeyByteString);
        managedPubkeys.Value.Add(ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(newPubkey)));
        State.ManagedCandidatePubkeysMap[Context.Sender] = managedPubkeys;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L46-49)
```csharp
        var newAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[input.Admin] ?? new PubkeyList();
        if (!newAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            newAdminManagedPubkeys.Value.Add(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[input.Admin] = newAdminManagedPubkeys;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L51-54)
```csharp
        var oldAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender] ?? new PubkeyList();
        if (oldAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            oldAdminManagedPubkeys.Value.Remove(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[Context.Sender] = oldAdminManagedPubkeys;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L104-106)
```csharp
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L129-131)
```csharp
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
```

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L73-73)
```csharp
    public MappedState<Address, PubkeyList> ManagedCandidatePubkeysMap { get; set; }
```
