# Audit Report

## Title
Insufficient Alternative Selection Allows Banned Miners to Remain Active in Consensus

## Summary
The Election contract's `GetMinerReplacementInformation()` function can return fewer alternative candidates than the number of banned miners requiring replacement. The consensus contract only replaces miners up to the count of alternatives provided, allowing unreplaced banned miners to remain in the active validator set and continue producing blocks.

## Finding Description

**Root Cause Analysis:**

The vulnerability exists in the miner replacement mechanism across two contracts:

In the Election contract's `GetMinerReplacementInformation()`, alternative candidates are selected using `Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count)` [1](#0-0) , limiting alternatives to available candidates. When this produces insufficient alternatives, the function attempts to supplement with initial miners using `Math.Min(diff, State.InitialMiners.Value.Value.Count)` [2](#0-1) .

However, after filtering for banned and current miners, the final `alternativeCandidates.Count` can be less than `evilMinersPubKeys.Count`, and the function returns this mismatched result [3](#0-2) .

**Consumption in Consensus Contract:**

The consensus contract receives this replacement information and processes it with a loop that iterates only `minerReplacementInformation.AlternativeCandidatePubkeys.Count` times [4](#0-3) . 

For each iteration, it:
1. Calls `UpdateCandidateInformation()` to mark the evil miner as banned
2. Removes the evil miner from `currentRound.RealTimeMinersInformation`
3. Adds the alternative candidate

Evil miners at indices beyond `AlternativeCandidatePubkeys.Count` are never processed - they remain in `currentRound.RealTimeMinersInformation` without being marked as evil or removed.

**Why Validation Fails:**

The `PreCheck()` validation only verifies that a miner exists in the current or previous round's miner list [5](#0-4) . It does not check the Election contract's `State.BannedPubkeyMap` to verify if a miner is banned.

Similarly, the `MiningPermissionValidationProvider` only checks if the sender exists in `RealTimeMinersInformation.Keys` [6](#0-5) .

**Attack Execution Path:**

1. Multiple miners are marked as banned via `UpdateCandidateInformation()` with `IsEvilNode = true`, setting `State.BannedPubkeyMap[pubkey] = true` [7](#0-6) 
2. During round generation, consensus calls `GetMinerReplacementInformation()` [8](#0-7) 
3. `GetEvilMinersPubkeys()` identifies all banned miners from the current miner list [9](#0-8) 
4. If insufficient alternatives exist, some evil miners remain unreplaced in the consensus round
5. These miners pass all validation checks and continue mining

## Impact Explanation

**Consensus Security Breach:**

This vulnerability directly violates the fundamental security invariant that banned miners must be immediately excluded from consensus participation. Miners banned for malicious behavior (detected attacks, protocol violations, double-signing) can continue producing blocks and earning rewards.

**Quantified Impact:**
- **Byzantine Tolerance Violation**: If multiple coordinating attackers are banned simultaneously but remain active due to insufficient alternatives, the BFT safety threshold may be compromised
- **Reward Misallocation**: Banned miners continue earning block production rewards that should be distributed to legitimate validators
- **Prolonged Attack Window**: Malicious miners can continue their attacks even after detection and banning

**Affected Parties:**
- Network security degrades for all participants
- Legitimate miners lose potential rewards and block production slots
- Token holders bear increased risk of consensus compromise

## Likelihood Explanation

**Triggering Conditions:**

This is a protocol-level flaw that occurs automatically when:
1. Multiple miners are banned simultaneously (e.g., 5+ miners in a network of 17)
2. Limited candidate pool exists (< 10 qualified candidates available)  
3. Initial miners are depleted (already active as miners or themselves banned)

**Realistic Scenario:**
- Network detects coordinated misbehavior and bans 5 miners
- Only 3 alternative candidates exist after filtering
- 2 initial miners available, but 1 is already an active miner and 1 is banned
- Result: Only 3 evil miners replaced, 2 remain active in consensus

**Execution Practicality:**
- No attacker action required - occurs through normal protocol operations
- No special privileges needed
- No timing or transaction manipulation necessary
- Deterministic outcome based on state conditions

The probability is **Medium-to-High** in realistic network conditions, particularly during:
- Mass detection of coordinated attacks
- Early chain stages with limited validator candidates
- Low election participation periods

## Recommendation

**Fix the Replacement Loop:**

The consensus contract should handle all identified evil miners, not just those with alternatives. Modify the replacement logic to:

1. Process ALL evil miners in the loop (iterate `EvilMinerPubkeys.Count` times)
2. For miners with alternatives, perform the replacement
3. For miners without alternatives, mark them as evil via `UpdateCandidateInformation()` and remove them from `currentRound.RealTimeMinersInformation` without adding a replacement
4. Adjust the miner list size accordingly

**Add Banned Status Validation:**

Enhance `PreCheck()` or add a validation provider that cross-checks miners against the Election contract's `State.BannedPubkeyMap` before allowing block production.

**Prevent Undersized Miner Sets:**

Add assertions to ensure the active miner count never falls below the minimum required for BFT security after removing banned miners without sufficient replacements.

## Proof of Concept

```csharp
[Fact]
public async Task InsufficientAlternativesAllowsBannedMinersToRemainActive()
{
    // Setup: 17 active miners, ban 5 of them
    // Candidate pool: 2 qualified candidates + 1 available initial miner = 3 alternatives total
    
    // Step 1: Mark 5 miners as evil
    var evilMiners = new[] { "miner1", "miner2", "miner3", "miner4", "miner5" };
    foreach (var miner in evilMiners)
    {
        await ElectionStub.UpdateCandidateInformation.SendAsync(new UpdateCandidateInformationInput
        {
            Pubkey = miner,
            IsEvilNode = true
        });
    }
    
    // Step 2: Get replacement information
    var replacementInfo = await ElectionStub.GetMinerReplacementInformation.CallAsync(
        new GetMinerReplacementInformationInput
        {
            CurrentMinerList = { /* all 17 current miners */ }
        });
    
    // Verify: Only 3 alternatives returned for 5 evil miners
    replacementInfo.EvilMinerPubkeys.Count.ShouldBe(5);
    replacementInfo.AlternativeCandidatePubkeys.Count.ShouldBe(3); // INSUFFICIENT
    
    // Step 3: Trigger round generation (calls replacement logic internally)
    await ConsensusStub.NextRound.SendAsync(new NextRoundInput { /* ... */ });
    
    // Step 4: Verify banned miners 4 and 5 remain in active miner set
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    currentRound.RealTimeMinersInformation.Keys.ShouldContain("miner4"); // STILL ACTIVE
    currentRound.RealTimeMinersInformation.Keys.ShouldContain("miner5"); // STILL ACTIVE
    
    // Step 5: Verify these banned miners can still produce blocks
    var block = await BannedMiner4.UpdateValue.SendAsync(new UpdateValueInput { /* ... */ });
    block.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // SUCCEEDS
}
```

## Notes

This vulnerability represents a critical gap in the consensus security model. The miner replacement mechanism was designed to handle evil node detection, but the implementation allows banned miners to remain active when alternatives are insufficient. The fix must ensure that banned miners are unconditionally removed from consensus participation, even if it temporarily reduces the active miner count below the target, as maintaining banned miners poses a greater security risk than operating with fewer validators.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L376-377)
```csharp
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L386-391)
```csharp
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L394-398)
```csharp
        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-404)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L311-339)
```csharp
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```
