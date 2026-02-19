### Title
Admin Can Steal Locked Election Tokens via Pubkey Replacement

### Summary
A malicious admin can steal the 100,000 ELF tokens locked during election announcement by replacing the candidate's public key with a pubkey they control, then calling QuitElection. The tokens will be sent to the admin's address instead of the original candidate's address.

### Finding Description

The vulnerability exists in the interaction between `AnnounceElection`, `ReplaceCandidatePubkey`, and `QuitElection` functions.

When a candidate announces election using `AnnounceElection`: [1](#0-0) 

The admin address is set at line 103, and tokens are locked via `LockCandidateNativeToken()` at line 108. Critically, the `CandidateSponsorMap` is NOT set in this flow (it's only set in `AnnounceElectionFor`). [2](#0-1) 

The admin can then call `ReplaceCandidatePubkey`: [3](#0-2) 

At line 181, only the admin can call this function. The critical flaw occurs here: [4](#0-3) 

The sponsor mapping is transferred (null to null for `AnnounceElection` flow), and the candidate information including the original AnnouncementTransactionId is transferred: [5](#0-4) 

Finally, the admin calls `QuitElection`: [6](#0-5) 

At line 240, the original lockId is retrieved. At line 245, tokens are sent to `State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes)`. Since CandidateSponsorMap is null, tokens go to `Address.FromPublicKey(pubkeyBytes)` - which is the admin's address if they used their own pubkey in the replacement.

The root cause is that `ReplaceCandidatePubkey` doesn't verify the new pubkey is controlled by the original candidate, and `QuitElection` uses the current pubkey to derive the token recipient address when no sponsor is set.

### Impact Explanation

Direct fund theft of 100,000 ELF tokens per candidate: [7](#0-6) 

Every candidate that uses `AnnounceElection` (not `AnnounceElectionFor`) and sets an external admin is vulnerable. The candidate has no mechanism to recover the stolen tokens once the admin executes this attack. This breaks the critical invariant that locked tokens must be returned to the rightful owner (candidate or sponsor).

At 100,000 ELF per candidate, with potentially dozens of candidates in the system, the total exposure could exceed millions of dollars. This completely undermines trust in the election system.

### Likelihood Explanation

The attack requires:
1. Admin privileges - explicitly granted by candidates during announcement (required input at line 101)
2. Two transaction calls: `ReplaceCandidatePubkey` + `QuitElection`
3. A pubkey controlled by the admin (trivially available - just generate a new keypair)

Attack complexity is LOW - straightforward 2-step process with no timing constraints, no need to win any races, and no external dependencies. The precondition (being set as admin) is explicitly granted by candidates who trust the admin address. 

Candidates have no way to detect this attack before execution. Once executed, the theft is permanent. The attack can be executed immediately after announcement with no waiting period. Economic rationality is extremely high: steal 100,000 ELF for the cost of 2 transaction fees (negligible).

The only constraint is line 191 which prevents using a pubkey that's already a candidate, but the admin can use any other pubkey including a freshly generated one: [8](#0-7) 

### Recommendation

Add verification in `QuitElection` to ensure tokens are returned to the original sponsor/candidate, not the current pubkey owner:

1. Add a new state mapping: `MappedState<Hash, Address> AnnouncementSponsorMap` to store the original token payer indexed by announcement transaction ID
2. In `LockCandidateNativeToken` (called during announcement), store the original payer: `State.AnnouncementSponsorMap[lockId] = Context.Sender`
3. In `QuitElection`, retrieve the original sponsor from the announcement transaction ID: `var originalSponsor = State.AnnouncementSponsorMap[lockId]`
4. Modify the token transfer recipient to: `originalSponsor ?? State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes)`

This ensures tokens always return to whoever originally paid them, regardless of any pubkey replacements that occur afterward.

Add comprehensive test cases:
- Verify admin cannot steal tokens via `ReplaceCandidatePubkey` + `QuitElection` sequence
- Verify tokens return to original candidate after pubkey replacement
- Verify tokens return to sponsor in `AnnounceElectionFor` flow after replacement
- Test multiple replacement chains to ensure original sponsor is always preserved

### Proof of Concept

**Initial State:**
- Candidate has 200,000 ELF balance
- Admin has 0 ELF balance
- Candidate generates keypair with pubkey: `candidatePubkey`
- Admin controls a keypair with pubkey: `adminPubkey`

**Step 1:** Candidate calls `AnnounceElection(adminAddress)` with their keypair signature
- Result: 100,000 ELF locked from candidate's address
- Candidate balance: 100,000 ELF
- `State.CandidateAdmins[candidatePubkey] = adminAddress`
- `State.CandidateSponsorMap[candidatePubkey]` = null (not set)

**Step 2:** Admin calls `ReplaceCandidatePubkey(oldPubkey=candidatePubkey, newPubkey=adminPubkey)`
- Authorization passes (admin is authorized at line 181)
- `State.CandidateSponsorMap[adminPubkey] = State.CandidateSponsorMap[candidatePubkey] = null`
- `State.CandidateInformationMap[adminPubkey]` now contains original AnnouncementTransactionId
- Admin's pubkey is now registered as the candidate

**Step 3:** Admin calls `QuitElection(adminPubkey)`
- `lockId = State.CandidateInformationMap[adminPubkey].AnnouncementTransactionId` (original tx id)
- Tokens retrieved from virtual address derived from original lockId
- Tokens sent to: `State.CandidateSponsorMap[adminPubkey] ?? Address.FromPublicKey(adminPubkeyBytes)`
- Since sponsor is null: tokens sent to `Address.FromPublicKey(adminPubkeyBytes)` = admin's address
- Admin balance: 100,000 ELF

**Expected Result:** 100,000 ELF should return to candidate's address  
**Actual Result:** 100,000 ELF goes to admin's address (theft successful)

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-119)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;

        LockCandidateNativeToken();

        AddCandidateAsOption(pubkey);

        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L177-195)
```csharp
    private void LockCandidateNativeToken()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Lock the token from sender for deposit of announce election
        var lockId = Context.OriginTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        var sponsorAddress = Context.Sender;
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = sponsorAddress,
            To = lockVirtualAddress,
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Lock for announcing election."
        });
    }
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
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
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L191-191)
```csharp
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L237-243)
```csharp
        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L320-321)
```csharp
        State.CandidateSponsorMap[newPubkey] = State.CandidateSponsorMap[oldPubkey];
        State.CandidateSponsorMap.Remove(oldPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```
