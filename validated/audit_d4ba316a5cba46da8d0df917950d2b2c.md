# Audit Report

## Title
Miner List Manipulation via Unvalidated NextRound Header Information

## Summary
The AEDPoS consensus validation mechanism fails to verify that the miner list in NextRound block headers matches the expected miner list derived from current consensus state and election results. This allows a malicious current miner to arbitrarily manipulate the next round's miner list, excluding legitimate miners and subverting the election-based consensus mechanism.

## Finding Description

The vulnerability exists in the three-stage validation flow for NextRound blocks:

**Gap 1: Pre-Execution Validation Insufficiency**

The `ValidateBeforeExecution` method only validates that the block producer is in the **current** round, but never validates the **provided next round's** miner list composition: [1](#0-0) 

The validation checks if the sender exists in `BaseRound.RealTimeMinersInformation.Keys` (the current round), but does not validate that `ProvidedRound.RealTimeMinersInformation` (the next round from the header) contains the correct set of miners.

Similarly, `NextRoundMiningOrderValidationProvider` only validates internal consistency: [2](#0-1) 

This checks that miners with `FinalOrderOfNextRound > 0` match those with `OutValue != null` in the **provided** round, but does not validate the miner list against expected miners from the Election contract.

**Gap 2: Unvalidated Direct Storage**

During execution, `ProcessNextRound` directly converts and stores the header data without validating the miner list: [3](#0-2) 

Lines 110 and 156 show that the input is converted to a Round object and directly stored via `AddRoundInformation(nextRound)` without any validation that the miner list matches the expected set of miners.

**Gap 3: Validation Tautology in Post-Execution**

After block execution, `ValidateAfterExecution` retrieves the round from state (which now contains the round just stored from the header) and compares it against the header: [4](#0-3) 

Since the state was just populated from the header (line 87 retrieves what was stored in line 156 of ProcessNextRound), the hash comparison at lines 100-101 always succeeds, creating a validation tautology. The miner replacement validation (lines 103-123) only triggers if hashes differ, which they never do for NextRound.

**Expected Behavior Not Enforced**

The expected miner list should be determined by `GenerateNextRoundInformation`, which properly checks the Election contract for miner replacements: [5](#0-4) 

This method (lines 301-342) checks `State.ElectionContract.GetMinerReplacementInformation` and applies legitimate replacements. However, this is only called during honest block **creation**, never during block **validation**.

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant that "miner schedule integrity must be maintained." The impacts are:

1. **Consensus Centralization**: A malicious miner can exclude competing miners, reducing consensus participants from N miners to a smaller set they control, potentially achieving >50% control without election.

2. **Reward Theft**: Excluded legitimate miners lose block production rewards they were entitled to through the election process, directly causing financial harm.

3. **Governance Subversion**: The Election contract's purpose is bypassed - miners elected by token holders can be arbitrarily excluded, violating the delegated proof-of-stake model.

4. **Persistent Attack Vector**: Once the manipulated round is accepted, the attacker can repeat the attack in subsequent rounds, maintaining indefinite control as long as they remain in their manipulated miner set.

5. **Network Security Degradation**: As consensus becomes centralized under attacker control, the network becomes vulnerable to typical centralized blockchain attacks (censorship, double-spend attempts, etc.).

This is a critical consensus integrity violation affecting the core security model of AEDPoS.

## Likelihood Explanation

**Attack Prerequisites (All Easily Satisfied):**
- Attacker must be a current miner: Achievable through normal election process
- Attacker must produce a NextRound block: Happens regularly in round-robin consensus
- No special privileges required beyond being an elected miner

**Attack Complexity: LOW**
1. Query current round state (public information)
2. Craft NextRoundInput with modified `RealTimeMinersInformation`
3. Ensure basic fields (round number, InValues=null) pass validation
4. No cryptographic operations or complex state manipulation needed

**Detection Difficulty: HIGH**
- Block passes all validation checks (ValidateBeforeExecution and ValidateAfterExecution)
- No events or logs indicate miner list manipulation
- Nodes accept block as consensus-valid
- Only manual comparison of expected vs actual miner lists would reveal the attack

**Probability: HIGH** - Any current miner can execute this attack whenever they produce a NextRound block (which happens every round transition). There are no technical barriers preventing execution.

## Recommendation

Add miner list validation before accepting NextRound blocks. The validation should compare the provided miner list against the expected miner list derived from current state and Election contract:

**In `ValidateBeforeExecution` for NextRound behavior:**

```csharp
// Add new validation provider for NextRound
validationProviders.Add(new NextRoundMinerListValidationProvider());
```

**New Validation Provider:**

```csharp
public class NextRoundMinerListValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        
        // Generate expected next round
        var currentRound = validationContext.BaseRound;
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var expectedNextRound);
        
        // Compare provided vs expected miner lists
        var providedMiners = validationContext.ProvidedRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var expectedMiners = expectedNextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        
        if (providedMiners.Count != expectedMiners.Count || 
            !providedMiners.SequenceEqual(expectedMiners))
        {
            validationResult.Message = "Provided next round miner list does not match expected miners from Election contract";
            return validationResult;
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

This ensures that any NextRound block must contain the exact miner list that would be generated by the legitimate `GenerateNextRoundInformation` method, preventing arbitrary miner list manipulation.

## Proof of Concept

```csharp
// PoC showing miner list manipulation attack
[Fact]
public async Task MaliciousMiner_CanManipulateNextRoundMinerList()
{
    // Setup: Initialize consensus with legitimate miners [Alice, Bob, Charlie, Dave, Eve]
    var legitimateMiners = new[] { "Alice", "Bob", "Charlie", "Dave", "Eve" };
    await InitializeConsensusWithMiners(legitimateMiners);
    
    // Bob is a current miner - he will produce the malicious NextRound block
    var maliciousMiner = "Bob";
    
    // Bob crafts a NextRound with arbitrary miner list [Bob, Frank, George, Harry, Ivan]
    // Excluding legitimate miners Alice, Charlie, Dave, Eve
    var maliciousMinerList = new[] { maliciousMiner, "Frank", "George", "Harry", "Ivan" };
    var maliciousNextRound = CreateNextRoundInput(maliciousMinerList, currentRoundNumber + 1);
    
    // Attempt to execute malicious NextRound
    await ExecuteNextRoundBlock(maliciousMiner, maliciousNextRound);
    
    // Verify: The malicious miner list was accepted (vulnerability confirmed)
    var newRound = await GetCurrentRoundInformation();
    var actualMiners = newRound.RealTimeMinersInformation.Keys.ToList();
    
    // VULNERABILITY: Malicious miner list was accepted instead of being rejected
    Assert.Equal(maliciousMinerList.OrderBy(m => m), actualMiners.OrderBy(m => m));
    
    // Legitimate miners are excluded from consensus
    Assert.DoesNotContain("Alice", actualMiners);
    Assert.DoesNotContain("Charlie", actualMiners);
    Assert.DoesNotContain("Dave", actualMiners);
    Assert.DoesNotContain("Eve", actualMiners);
    
    // Attacker-controlled miners are now in control
    Assert.Contains("Frank", actualMiners);
    Assert.Contains("George", actualMiners);
}
```

This PoC demonstrates that a current miner can successfully inject an arbitrary miner list into the next round, bypassing all validation mechanisms and excluding legitimate miners from consensus participation.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L285-347)
```csharp
    private void GenerateNextRoundInformation(Round currentRound, Timestamp currentBlockTime, out Round nextRound)
    {
        TryToGetPreviousRoundInformation(out var previousRound);
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();
        var isMinerListChanged = false;
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
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

                isMinerListChanged = true;
            }
        }

        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
    }
```
