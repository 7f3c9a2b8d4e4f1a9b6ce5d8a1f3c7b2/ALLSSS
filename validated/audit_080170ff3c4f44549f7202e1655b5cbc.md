# Audit Report

## Title
Unauthorized Admin Takeover via AnnounceElectionFor After Candidate Quits Election

## Summary
The `AnnounceElectionFor` method unconditionally overwrites the `CandidateAdmins` mapping for quit candidates, allowing unauthorized admin takeover. When a candidate quits via `QuitElection`, the admin mapping is not cleared, and any attacker can subsequently call `AnnounceElectionFor` to overwrite the admin address, gaining complete control over the candidate including the ability to replace the pubkey, force quit, and hijack validator positions.

## Finding Description

The vulnerability arises from three interconnected flaws in the Election contract's candidate management logic:

**Root Cause 1 - Stale Admin State After Quit:**

When `QuitElection` executes, it performs cleanup by setting `IsCurrentCandidate = false` [1](#0-0)  and removes the pubkey from the reverse mapping `ManagedCandidatePubkeysMap` [2](#0-1) . However, the method critically fails to clear the `State.CandidateAdmins[initialPubkey]` mapping, leaving stale admin state.

**Root Cause 2 - Unconditional Admin Overwrite:**

The `AnnounceElectionFor` method unconditionally sets the admin without checking if an admin already exists: [3](#0-2) . This line executes with no authorization validation against the previous admin owner.

**Root Cause 3 - Re-announcement Without Admin Validation:**

The private `AnnounceElection` helper explicitly permits re-announcing quit candidates by checking if the candidate is not current: [4](#0-3) . When a `candidateInformation` exists but `IsCurrentCandidate` is false, the method allows the announcement to proceed, enabling the admin overwrite.

**Attack Execution Path:**

1. Legitimate candidate Alice announces election with admin address `A`
2. Alice quits election - admin mapping `CandidateAdmins[Alice_pubkey]` still equals `A`
3. Attacker Bob calls `AnnounceElectionFor(Alice_pubkey, B)` with announcement fee
4. Private helper allows re-announcement since `!IsCurrentCandidate` is true
5. Line 128 overwrites: `CandidateAdmins[Alice_pubkey] = B` 
6. Bob now controls all admin operations for Alice's candidate

## Impact Explanation

**Critical Authorization Bypass:**

The attacker gains complete administrative control verified through permission checks in privileged operations:

1. **ReplaceCandidatePubkey** requires sender to be the admin [5](#0-4) , allowing the attacker to replace the victim's pubkey with one they control, inheriting all voting weight and validator eligibility.

2. **QuitElection** validates sender is the admin [6](#0-5) , enabling forced quit attacks.

3. **SetCandidateAdmin** when admin exists, only current admin can change it [7](#0-6) , allowing attacker to consolidate permanent control.

**Validator Position Hijacking:**

By replacing the pubkey, attackers inherit the candidate's accumulated voting weight, historical reputation (produced blocks, term count), and position in the data center ranking list [8](#0-7) . This enables validator election manipulation and unauthorized consensus participation rights.

The vulnerability violates the fundamental security invariant that admin control should only transfer through explicit authorization by the legitimate owner or governance mechanisms.

## Likelihood Explanation

**Attack Feasibility: HIGH**

The vulnerability is trivially exploitable:
- **Access Requirements:** None - any user can call public `AnnounceElectionFor`
- **Cost:** Only the announcement deposit (`ElectionContractConstants.LockTokenForElection`), which is recoverable by quitting again
- **Preconditions:** Target candidate must have quit (common in normal validator operations)
- **Complexity:** Single transaction attack requiring no special timing or conditions

**Attack Scenario:**

Validators regularly quit election when rotating out, changing infrastructure, or retiring. Each quit candidate becomes permanently vulnerable. An attacker can:
1. Monitor `GetCandidateInformation` for quit candidates
2. Call `AnnounceElectionFor(victim_pubkey, attacker_address)`
3. Immediately execute admin operations like `ReplaceCandidatePubkey`

The fee is recoverable and the vulnerability persists indefinitely, making this economically rational for attackers seeking validator positions or wishing to disrupt consensus.

## Recommendation

**Fix 1: Clear Admin Mapping on Quit**

Modify `QuitElection` to clear the admin mapping:
```csharp
// After line 254 in QuitElection
State.CandidateAdmins.Remove(initialPubkey);
```

**Fix 2: Add Authorization Check in AnnounceElectionFor**

Modify `AnnounceElectionFor` to prevent overwriting existing admins:
```csharp
// Before line 128
var existingAdmin = State.CandidateAdmins[pubkey];
Assert(existingAdmin == null, "Candidate already has an admin. Use SetCandidateAdmin instead.");
```

**Fix 3: Validate Admin Continuity**

For re-announcements, verify the caller is the existing admin or the pubkey owner:
```csharp
// In AnnounceElection helper, before line 159
if (candidateInformation != null && !candidateInformation.IsCurrentCandidate)
{
    var existingAdmin = State.CandidateAdmins[State.InitialPubkeyMap[pubkey] ?? pubkey];
    if (existingAdmin != null)
    {
        // This will be checked in AnnounceElectionFor - don't allow re-announcement with existing admin
        Assert(false, "Cannot re-announce candidate with existing admin without authorization.");
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AdminTakeover_QuitCandidate_Vulnerability_Test()
{
    // Setup: Alice announces election with herself as admin
    var aliceKeyPair = ValidationDataCenterKeyPairs[0];
    var aliceAdmin = Address.FromPublicKey(aliceKeyPair.PublicKey);
    
    await AnnounceElectionAsync(aliceKeyPair, aliceAdmin);
    
    // Verify Alice is admin
    var adminBefore = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = aliceKeyPair.PublicKey.ToHex() });
    adminBefore.ShouldBe(aliceAdmin);
    
    // Alice quits election
    await QuitElectionAsync(aliceKeyPair);
    
    // Admin mapping still exists (vulnerability)
    var adminAfterQuit = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = aliceKeyPair.PublicKey.ToHex() });
    adminAfterQuit.ShouldBe(aliceAdmin); // NOT CLEARED
    
    // Attack: Bob announces election for Alice's pubkey with Bob as admin
    var bobKeyPair = ValidationDataCenterKeyPairs[1];
    var bobAdmin = Address.FromPublicKey(bobKeyPair.PublicKey);
    var bobStub = GetElectionContractTester(bobKeyPair);
    
    await bobStub.AnnounceElectionFor.SendAsync(new AnnounceElectionForInput
    {
        Pubkey = aliceKeyPair.PublicKey.ToHex(),
        Admin = bobAdmin
    });
    
    // Verify: Bob is now admin (TAKEOVER SUCCESSFUL)
    var adminAfterAttack = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = aliceKeyPair.PublicKey.ToHex() });
    adminAfterAttack.ShouldBe(bobAdmin); // ADMIN HIJACKED
    
    // Bob can now perform admin operations like ReplaceCandidatePubkey
    var newPubkey = ValidationDataCenterKeyPairs[2].PublicKey.ToHex();
    await bobStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = aliceKeyPair.PublicKey.ToHex(),
        NewPubkey = newPubkey
    });
    
    // Verify replacement succeeded with Bob's authority
    var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidates.Value.Select(p => p.ToHex()).ShouldContain(newPubkey);
    candidates.Value.Select(p => p.ToHex()).ShouldNotContain(aliceKeyPair.PublicKey.ToHex());
}
```

**Notes:**

This vulnerability represents a critical failure in authorization state management. The attack requires no special privileges and can be executed against any candidate who has quit election. The unclearable admin state combined with unconditional overwrites creates a permanent authorization bypass affecting validator security and consensus integrity. The fix requires ensuring admin mappings are properly cleared during quit operations and adding authorization checks before allowing admin reassignment.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L37-38)
```csharp
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L128-128)
```csharp
        State.CandidateAdmins[pubkey] = admin;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-162)
```csharp
        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L236-236)
```csharp
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L252-254)
```csharp
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L270-275)
```csharp
        var managedCandidatePubkey = State.ManagedCandidatePubkeysMap[Context.Sender];
        managedCandidatePubkey.Value.Remove(ByteString.CopyFrom(pubkeyBytes));
        if (managedCandidatePubkey.Value.Any())
            State.ManagedCandidatePubkeysMap[Context.Sender] = managedCandidatePubkey;
        else
            State.ManagedCandidatePubkeysMap.Remove(Context.Sender);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L199-205)
```csharp
        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;
```
