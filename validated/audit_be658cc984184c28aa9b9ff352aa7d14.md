# Audit Report

## Title
Miners Lose Term Credit When Replacing Pubkey Before Term End Due to Stale Round Data

## Summary
When a miner replaces their public key via `ReplaceCandidatePubkey`, the election contract transfers their candidate information to the new pubkey and removes the old pubkey's entry. However, the consensus contract's stored round data for previous rounds retains the old pubkey. When `TakeSnapshot` is called at term end, it retrieves pubkeys from stored round data and attempts to update candidate information using the old pubkey, which no longer has an entry. This causes the private `UpdateCandidateInformation` method to return early, preventing miners from receiving credit for terms where they successfully produced blocks.

## Finding Description

The vulnerability stems from a data synchronization issue between the Election and Consensus contracts during pubkey replacement.

**Root Cause - Candidate Information Removal:**

When `ReplaceCandidatePubkey` executes, it explicitly removes the old pubkey's candidate information from state storage: [1](#0-0) 

The candidate information is moved to the new pubkey, but the old pubkey entry is completely removed from the state map.

**Incomplete Consensus State Update:**

The election contract then notifies the consensus contract via `RecordCandidateReplacement`, but this method only updates the **current** round's `RealTimeMinersInformation`: [2](#0-1) 

Previous rounds stored in state remain unchanged and continue to reference the old pubkey.

**Failure at Term End:**

When a term ends, the consensus contract calls `TakeSnapshot` on the Election contract: [3](#0-2) 

The method retrieves pubkeys from stored round data: [4](#0-3) 

For each pubkey, the private `UpdateCandidateInformation` method is called. This method has a critical early return when candidate information is null: [5](#0-4) 

Since the old pubkey's `candidateInformation` was removed during replacement, the method returns at line 485 without updating the `Terms` list (line 486) or the `ContinualAppointmentCount` (lines 488-490).

**Existing Protection Not Applied:**

The codebase includes a `GetNewestPubkey` function specifically designed to resolve old pubkeys to their newest replacements: [6](#0-5) 

This function is correctly used in other contexts such as the `Withdraw` method: [7](#0-6) 

And in `GetPreviousTermSnapshotWithNewestPubkey`: [8](#0-7) 

However, `TakeSnapshot` does **not** call `GetNewestPubkey` before attempting to update candidate information, causing it to use the stale old pubkey.

## Impact Explanation

**Direct Impact:**

Miners who replace their public keys lose historical participation records for the term in which the replacement occurred. The protocol documentation defines these fields as: [9](#0-8) 

When the `Terms` list is not updated, the candidate's participation history becomes incomplete. When `ContinualAppointmentCount` is not updated, the continuity tracking mechanism breaks, potentially affecting future eligibility or reputation calculations.

**Severity Justification:**

This is a **High** severity issue because:
- It violates a fundamental protocol invariant: miners should receive credit for terms in which they actively participated and produced blocks
- The `Terms` list and `ContinualAppointmentCount` are part of the `CandidateInformation` structure that voters rely on to evaluate miner performance and history
- Historical participation records are critical for transparency and accountability in a DPoS consensus system
- Future protocol logic may depend on these fields for reward calculations, eligibility checks, or reputation scoring

**Affected Parties:**
- Miners who use the legitimate pubkey replacement feature lose their participation history
- Voters cannot make informed decisions based on accurate candidate history
- Off-chain systems, block explorers, and UI applications display incorrect miner statistics
- The protocol's accountability and transparency mechanisms are undermined

## Likelihood Explanation

**Trigger Conditions:**

The vulnerability triggers automatically when:
1. A miner calls `ReplaceCandidatePubkey` (requires only being a registered candidate with admin privileges)
2. The current term ends
3. The consensus contract calls `TakeSnapshot` to finalize the term

**Probability Assessment:**

This issue has **High** likelihood because:
- The `ReplaceCandidatePubkey` feature is specifically designed for key rotation scenarios, which are common operational requirements for node operators
- Miners may need to replace keys for legitimate security reasons: compromised keys, hardware failures, operational changes, or infrastructure updates
- There is no warning mechanism to alert users that replacing their pubkey will cause them to lose term credits
- The vulnerability occurs deterministically every time the conditions are met
- Key rotation is a best practice in long-running blockchain systems, making this a natural operation that miners will perform

The vulnerability does not require any attacker privileges or malicious intent—it affects legitimate users of the system's intended functionality.

## Recommendation

Modify the `TakeSnapshot` method to call `GetNewestPubkey` for each pubkey retrieved from the previous term's miner list before attempting to update candidate information. This ensures that the update is applied to the current candidate information, not the removed old entry.

The fix should be applied in the `TakeSnapshot` method where it iterates through previous term miners:

```csharp
foreach (var pubkey in previousTermMinerList)
{
    var newestPubkey = GetNewestPubkey(pubkey);
    UpdateCandidateInformation(newestPubkey, input.TermNumber, previousTermMinerList);
}
```

This approach mirrors the pattern already used in `Withdraw`, `ChangeVotingOption`, and `GetPreviousTermSnapshotWithNewestPubkey` methods, ensuring consistency across the codebase.

## Proof of Concept

```csharp
[Fact]
public async Task TakeSnapshot_After_ReplaceCandidatePubkey_LosesTermCredit_Test()
{
    // Arrange: Set up a miner who is actively mining
    var oldKeyPair = ValidationDataCenterKeyPairs[0];
    var newKeyPair = ValidationDataCenterKeyPairs[1];
    var adminKeyPair = ValidationDataCenterKeyPairs[2];
    var adminAddress = Address.FromPublicKey(adminKeyPair.PublicKey);
    
    // Register and become a miner
    await AnnounceElectionAsync(oldKeyPair, adminAddress);
    await VoteToCandidate(VoterKeyPairs[0], oldKeyPair.PublicKey.ToHex(), 100_000_000_000, 120);
    
    // Advance to next term so miner is elected
    await NextTerm(InitialCoreDataCenterKeyPairs[0]);
    
    // Get initial candidate information
    var oldInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = oldKeyPair.PublicKey.ToHex() });
    var initialTermsCount = oldInfo.Terms.Count;
    var currentTerm = State.CurrentTermNumber.Value;
    
    // Act: Replace pubkey mid-term
    var adminStub = GetElectionContractTester(adminKeyPair);
    await adminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = oldKeyPair.PublicKey.ToHex(),
        NewPubkey = newKeyPair.PublicKey.ToHex()
    });
    
    // Verify old pubkey entry was removed
    var oldInfoAfterReplacement = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = oldKeyPair.PublicKey.ToHex() });
    oldInfoAfterReplacement.Pubkey.ShouldBe(oldKeyPair.PublicKey.ToHex());
    oldInfoAfterReplacement.IsCurrentCandidate.ShouldBeFalse();
    
    // New pubkey should have the information
    var newInfoBeforeSnapshot = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = newKeyPair.PublicKey.ToHex() });
    newInfoBeforeSnapshot.Terms.Count.ShouldBe(initialTermsCount);
    
    // Advance to term end and call TakeSnapshot
    await NextTerm(InitialCoreDataCenterKeyPairs[0]);
    
    // Assert: Verify the new pubkey's Terms list was NOT updated
    var newInfoAfterSnapshot = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = newKeyPair.PublicKey.ToHex() });
    
    // BUG: Terms list should include the previous term, but it doesn't
    newInfoAfterSnapshot.Terms.Count.ShouldBe(initialTermsCount); // Should be initialTermsCount + 1
    newInfoAfterSnapshot.Terms.ShouldNotContain(currentTerm); // Should contain the term where miner participated
    
    // The ContinualAppointmentCount is also not incremented
    // (assuming miner was in victories list)
}
```

## Notes

This vulnerability demonstrates a classic state synchronization issue between two contracts. The Election contract removes old pubkey state, but the Consensus contract maintains historical round data with old pubkeys. When these two states intersect during `TakeSnapshot`, the missing pubkey resolution causes miners to lose legitimate term credits. The fix is straightforward—apply the same `GetNewestPubkey` pattern that already exists elsewhere in the codebase.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L237-242)
```csharp
        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L353-357)
```csharp
    private string GetNewestPubkey(string pubkey)
    {
        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        return State.InitialToNewestPubkeyMap[initialPubkey] ?? initialPubkey;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L430-434)
```csharp
        var previousTermMinerList =
            State.AEDPoSContract.GetPreviousTermMinerPubkeyList.Call(new Empty()).Pubkeys.ToList();

        foreach (var pubkey in previousTermMinerList)
            UpdateCandidateInformation(pubkey, input.TermNumber, previousTermMinerList);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L481-492)
```csharp
    private void UpdateCandidateInformation(string pubkey, long lastTermNumber,
        List<string> previousMiners)
    {
        var candidateInformation = State.CandidateInformationMap[pubkey];
        if (candidateInformation == null) return;
        candidateInformation.Terms.Add(lastTermNumber);
        var victories = GetVictories(previousMiners);
        candidateInformation.ContinualAppointmentCount = victories.Contains(ByteStringHelper.FromHexString(pubkey))
            ? candidateInformation.ContinualAppointmentCount.Add(1)
            : 0;
        State.CandidateInformationMap[pubkey] = candidateInformation;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L136-146)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L464-472)
```csharp
    public override PubkeyList GetPreviousTermMinerPubkeyList(Empty input)
    {
        var lastRoundNumber = State.FirstRoundNumberOfEachTerm[State.CurrentTermNumber.Value].Sub(1);
        var lastRound = State.Rounds[lastRoundNumber];
        if (lastRound == null || lastRound.RoundId == 0) return new PubkeyList();
        return new PubkeyList
        {
            Pubkeys = { lastRound.RealTimeMinersInformation.Keys }
        };
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L650-654)
```csharp
        // Update Candidate's Votes information.
        var newestPubkey = GetNewestPubkey(votingRecord.Option);
        var candidateVotes = State.CandidateVotes[newestPubkey];

        Assert(candidateVotes != null, $"Newest pubkey {newestPubkey} is invalid. Old pubkey is {votingRecord.Option}");
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L148-151)
```csharp
        Context.LogDebug(() => "Getting snapshot and there's miner replaced during current term.");
        foreach (var bannedCandidate in bannedCandidates)
        {
            var newestPubkey = GetNewestPubkey(bannedCandidate);
```

**File:** protobuf/election_contract.proto (L368-375)
```text
    // The number of terms that the candidate is elected.
    repeated int64 terms = 2;
    // The number of blocks the candidate has produced.
    int64 produced_blocks = 3;
    // The time slot for which the candidate failed to produce blocks.
    int64 missed_time_slots = 4;
    // The count of continual appointment.
    int64 continual_appointment_count = 5;
```
