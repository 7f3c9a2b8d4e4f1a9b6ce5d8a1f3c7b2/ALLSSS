# Audit Report

## Title
Miner List Manipulation via Unvalidated NextRound Header Information

## Summary
The AEDPoS consensus validation mechanism fails to verify that the miner list in NextRound block headers matches the expected miner list derived from election results. This allows a malicious current miner to arbitrarily manipulate the next round's miner list, excluding legitimate miners and subverting the election-based consensus mechanism.

## Finding Description

The vulnerability exists in the three-stage validation flow for NextRound blocks:

**Gap 1: Pre-Execution Validation Insufficiency**

The `MiningPermissionValidationProvider` only validates that the block producer exists in the **current** round's miner list, but never validates the composition of the **provided next round's** miner list. [1](#0-0) 

The validation checks if the sender exists in `BaseRound.RealTimeMinersInformation.Keys` (the current round at time of validation), but does not validate that the next round's miner list in the header matches expected miners from the Election contract.

Similarly, `NextRoundMiningOrderValidationProvider` only validates internal consistency between miners with `FinalOrderOfNextRound > 0` and those with `OutValue != null`, but does not validate the actual miner list composition. [2](#0-1) 

**Gap 2: Unvalidated Direct Storage**

During execution, `ProcessNextRound` directly converts the input via `ToRound()` and stores it via `AddRoundInformation(nextRound)` without any validation that the miner list matches the expected set from the Election contract. [3](#0-2) 

The `ToRound()` method performs a direct field-by-field copy of `RealTimeMinersInformation` without any validation. [4](#0-3) 

**Gap 3: Validation Tautology in Post-Execution**

After block execution, `ValidateConsensusAfterExecution` retrieves the round from state (which now contains the round just stored from the header) and compares it against the header. [5](#0-4) 

Since `ProcessNextRound` updates the current round number before this validation executes [6](#0-5) , when `TryToGetCurrentRoundInformation` is called, it retrieves the exact round that was just stored from the header. For NextRound behavior (lines 89-97 show no transformation occurs), the hash comparison always succeeds, creating a validation tautology. The miner replacement validation that checks the Election contract (lines 103-123) only triggers if hashes differ, which they never do for NextRound.

**Expected Behavior Not Enforced**

The expected miner list should be determined by `GenerateNextRoundInformation`, which properly checks the Election contract for miner replacements via `State.ElectionContract.GetMinerReplacementInformation`. [7](#0-6) 

However, this method is only called during honest block **creation** via `GetConsensusExtraDataForNextRound` [8](#0-7) , never during block **validation**.

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant that "miner schedule integrity must be maintained according to election results." The impacts are:

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
3. Ensure basic fields pass validation (round number = current + 1, InValues = null)
4. Ensure internal consistency for `NextRoundMiningOrderValidationProvider`
5. No cryptographic operations or complex state manipulation needed

**Detection Difficulty: HIGH**
- Block passes all validation checks (ValidateConsensusBeforeExecution and ValidateConsensusAfterExecution)
- No events or logs indicate miner list manipulation
- Nodes accept block as consensus-valid
- Only manual comparison of expected vs actual miner lists would reveal the attack

**Probability: HIGH** - Any current miner can execute this attack whenever they produce a NextRound block (which happens every round transition). There are no technical barriers preventing execution.

## Recommendation

Add miner list validation during block validation by verifying the provided next round's miner list matches the expected list from the Election contract:

**In ValidateBeforeExecution for NextRound behavior:**
```
// After line 86 in AEDPoSContract_Validation.cs
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    // ADD: Validate miner list matches Election contract expectations
    validationProviders.Add(new MinerListValidationProvider());
    break;
```

**Create new MinerListValidationProvider:**
```
public class MinerListValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.NextRound)
            return new ValidationResult { Success = true };
            
        var providedMiners = validationContext.ProvidedRound.RealTimeMinersInformation.Keys.ToHashSet();
        var currentMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.ToHashSet();
        
        // Get expected replacements from Election contract
        var minerReplacementInfo = State.ElectionContract.GetMinerReplacementInformation.Call(
            new GetMinerReplacementInformationInput { CurrentMinerList = { currentMiners } });
            
        var expectedMiners = new HashSet<string>(currentMiners);
        for (var i = 0; i < minerReplacementInfo.EvilMinerPubkeys.Count; i++)
        {
            expectedMiners.Remove(minerReplacementInfo.EvilMinerPubkeys[i]);
            expectedMiners.Add(minerReplacementInfo.AlternativeCandidatePubkeys[i]);
        }
        
        if (!providedMiners.SetEquals(expectedMiners))
            return new ValidationResult { 
                Success = false, 
                Message = "Miner list in NextRound header does not match expected miner list from Election contract." 
            };
            
        return new ValidationResult { Success = true };
    }
}
```

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MinerCanManipulateNextRoundMinerList()
{
    // Setup: Initialize consensus with 5 miners
    var initialMiners = new[] { "Miner1", "Miner2", "Miner3", "Miner4", "Miner5" };
    await InitializeConsensusWithMiners(initialMiners);
    
    // Attacker is Miner1 and it's their turn to produce NextRound block
    var attackerPubkey = "Miner1";
    
    // Get current round
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Craft malicious NextRound with modified miner list (excluding Miner2 and Miner3)
    var maliciousNextRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        // Only include Miner1, Miner4, Miner5 - excluding Miner2 and Miner3
        RealTimeMinersInformation = {
            CreateMinerInfo(attackerPubkey, 1),
            CreateMinerInfo("Miner4", 2),
            CreateMinerInfo("Miner5", 3)
        }
    };
    
    // Ensure internal consistency for validation
    foreach (var miner in maliciousNextRound.RealTimeMinersInformation.Values)
    {
        miner.OutValue = Hash.FromString(miner.Pubkey);
        miner.FinalOrderOfNextRound = miner.Order;
    }
    
    // Submit the malicious NextRound transaction
    var result = await AEDPoSContractStub.NextRound.SendAsync(
        NextRoundInput.Create(maliciousNextRound, GenerateRandomNumber()));
    
    // Verify the attack succeeded
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify the manipulated miner list is now in state
    var newRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    newRound.RoundNumber.ShouldBe(currentRound.RoundNumber + 1);
    newRound.RealTimeMinersInformation.Count.ShouldBe(3); // Only 3 miners instead of 5
    newRound.RealTimeMinersInformation.Keys.ShouldNotContain("Miner2");
    newRound.RealTimeMinersInformation.Keys.ShouldNotContain("Miner3");
    
    // Miner2 and Miner3 are now excluded from consensus and lose rewards
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-21)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L285-345)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```
