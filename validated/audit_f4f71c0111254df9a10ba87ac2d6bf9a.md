# Audit Report

## Title
Candidate Admin Separation Invariant Can Be Bypassed Through AnnounceElectionFor

## Summary
The Election contract enforces an invariant that "Candidate cannot be others' admin" in the `AnnounceElection` method, but this critical check is absent from `AnnounceElectionFor` and `SetCandidateAdmin`. This allows any candidate to bypass the restriction and become an admin for multiple candidates, centralizing control over candidate slots and violating the intended decentralization guarantees of the election system.

## Finding Description

The Election contract maintains two related state mappings: `CandidateAdmins` (mapping pubkey to admin address) and `ManagedCandidatePubkeysMap` (mapping admin address to list of managed pubkeys). [1](#0-0) 

The `AnnounceElection` method explicitly enforces the separation invariant through a validation check that prevents addresses already managing candidates from becoming candidates themselves. This check verifies that the candidate's address is not already in `ManagedCandidatePubkeysMap`: [2](#0-1) 

However, the `AnnounceElectionFor` method completely omits this validation check, allowing the admin parameter to be set without verifying whether that admin is already a candidate: [3](#0-2) 

Similarly, `SetCandidateAdmin` allows changing a candidate's admin without checking if the new admin is already a candidate: [4](#0-3) 

**Exploitation Sequence:**
1. Alice calls `AnnounceElection(Alice)` - The check at line 102 passes because `ManagedCandidatePubkeysMap[Alice]` is initially null
2. After execution, Alice is a candidate and `ManagedCandidatePubkeysMap[Alice]` contains only Alice's pubkey
3. Alice calls `AnnounceElectionFor(BobPubkey, Alice)` - No validation prevents Alice from managing additional candidates
4. Result: `ManagedCandidatePubkeysMap[Alice]` now contains both Alice's and Bob's pubkeys, violating the invariant

## Impact Explanation

The candidate admin role carries significant privileges that enable centralization of control:

**Authorization Control:**

The admin can unilaterally set profit receivers for all managed candidates through the Treasury contract: [5](#0-4) 

The admin can force any managed candidate to quit the election: [6](#0-5) 

The admin can replace candidate public keys at will: [7](#0-6) 

**Governance Impact:**
- A single entity can control multiple candidate slots while appearing as separate candidates
- The admin can redirect mining rewards from managed candidates to their own address
- This undermines the decentralized election process by allowing vote manipulation through multiple controlled candidates
- Managed candidates lose autonomy over their candidacy, profits, and operational decisions

**Economic Impact:**
By setting profit receivers for managed candidates to their own address, the attacker can extract rewards earned by infrastructure they don't operate, effectively stealing mining rewards from legitimate node operators.

## Likelihood Explanation

**Accessibility:** Both `AnnounceElection` and `AnnounceElectionFor` are public RPC methods callable by any user without special privileges.

**Execution Requirements:** 
- Cost: Multiple candidate deposits (ElectionContractConstants.LockTokenForElection per candidate)
- Prerequisites: Sufficient token balance for deposits
- No timing constraints or complex state preconditions required

**Detection:** The vulnerability can be detected by querying managed pubkeys for candidate addresses using the `GetManagedPubkeys` view method: [8](#0-7) 

**Probability:** HIGH - The bypass requires only two simple transaction calls with no coordination or timing requirements. Any user with sufficient tokens can execute this attack immediately.

## Recommendation

Add the same invariant check to both `AnnounceElectionFor` and `SetCandidateAdmin` methods. Before setting an admin, verify that the admin address is not already a candidate:

```csharp
// In AnnounceElectionFor, after line 127:
var adminAddress = admin;
var candidateInformation = State.CandidateInformationMap[adminAddress.ToHex()];
Assert(candidateInformation == null || !candidateInformation.IsCurrentCandidate, 
    "Admin cannot be a current candidate.");

// In SetCandidateAdmin, after line 40:
var newAdminCandidateInfo = State.CandidateInformationMap[input.Admin.ToHex()];
Assert(newAdminCandidateInfo == null || !newAdminCandidateInfo.IsCurrentCandidate,
    "New admin cannot be a current candidate.");
```

Alternatively, convert addresses to pubkey format and check against the `Candidates` list to ensure the admin is not a candidate.

## Proof of Concept

```csharp
[Fact]
public async Task CandidateAdminSeparationInvariantBypass_Test()
{
    // Setup: Alice will be both a candidate and an admin for others
    var aliceKeyPair = ValidationDataCenterKeyPairs[0];
    var bobKeyPair = ValidationDataCenterKeyPairs[1];
    
    var aliceAddress = Address.FromPublicKey(aliceKeyPair.PublicKey);
    var aliceElectionStub = GetElectionContractTester(aliceKeyPair);
    var sponsorStub = GetElectionContractTester(ValidationDataCenterKeyPairs[2]);
    
    // Step 1: Alice announces election with herself as admin
    await aliceElectionStub.AnnounceElection.SendAsync(aliceAddress);
    
    // Verify Alice is now a candidate
    var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidates.Value.ShouldContain(ByteString.CopyFrom(aliceKeyPair.PublicKey));
    
    // Verify Alice manages her own pubkey
    var aliceManagedBefore = await ElectionContractStub.GetManagedPubkeys.CallAsync(aliceAddress);
    aliceManagedBefore.Value.Count.ShouldBe(1);
    aliceManagedBefore.Value.ShouldContain(ByteString.CopyFrom(aliceKeyPair.PublicKey));
    
    // Step 2: Sponsor announces Bob's candidacy with Alice as admin (BYPASSING INVARIANT)
    await sponsorStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Pubkey = bobKeyPair.PublicKey.ToHex(),
        Admin = aliceAddress
    });
    
    // Verify invariant is violated: Alice is a candidate AND manages Bob
    var aliceManagedAfter = await ElectionContractStub.GetManagedPubkeys.CallAsync(aliceAddress);
    aliceManagedAfter.Value.Count.ShouldBe(2); // Alice manages both herself and Bob
    aliceManagedAfter.Value.ShouldContain(ByteString.CopyFrom(aliceKeyPair.PublicKey));
    aliceManagedAfter.Value.ShouldContain(ByteString.CopyFrom(bobKeyPair.PublicKey));
    
    // Verify Alice can now exercise admin privileges over Bob
    var bobAdmin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = bobKeyPair.PublicKey.ToHex() });
    bobAdmin.ShouldBe(aliceAddress);
    
    // Alice can force Bob to quit election (demonstrating the impact)
    await aliceElectionStub.QuitElection.SendAsync(
        new StringValue { Value = bobKeyPair.PublicKey.ToHex() });
    
    // Verify Bob is no longer a candidate
    var candidatesAfterQuit = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidatesAfterQuit.Value.ShouldNotContain(ByteString.CopyFrom(bobKeyPair.PublicKey));
}
```

## Notes

The vulnerability represents a critical inconsistency in invariant enforcement. While `AnnounceElection` carefully prevents candidates from becoming admins for others, alternative code paths (`AnnounceElectionFor` and `SetCandidateAdmin`) allow this restriction to be bypassed. This enables centralization attacks where a single entity can control multiple candidate slots, manipulate voting through coordinated actions, and extract rewards from managed candidates. The fix requires adding the same validation check to all methods that establish admin relationships.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L68-73)
```csharp
    public MappedState<string, Address> CandidateAdmins { get; set; }

    /// <summary>
    ///     Admin address -> Pubkey
    /// </summary>
    public MappedState<Address, PubkeyList> ManagedCandidatePubkeysMap { get; set; }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L19-57)
```csharp
    public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

        // Permission check
        var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
            }
        }

        State.CandidateAdmins[pubkey] = input.Admin;

        var pubkeyByteString = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(pubkey));

        var newAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[input.Admin] ?? new PubkeyList();
        if (!newAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            newAdminManagedPubkeys.Value.Add(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[input.Admin] = newAdminManagedPubkeys;

        var oldAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender] ?? new PubkeyList();
        if (oldAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            oldAdminManagedPubkeys.Value.Remove(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[Context.Sender] = oldAdminManagedPubkeys;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L102-102)
```csharp
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-142)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
        var admin = input.Admin ?? Context.Sender;
        State.CandidateAdmins[pubkey] = admin;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
        LockCandidateNativeToken();
        AddCandidateAsOption(pubkey);
        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L236-236)
```csharp
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L427-430)
```csharp
    public override PubkeyList GetManagedPubkeys(Address input)
    {
        return State.ManagedCandidatePubkeysMap[input];
    }
```
