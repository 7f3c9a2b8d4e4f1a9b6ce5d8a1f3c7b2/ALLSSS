# Audit Report

## Title
Consensus Hijacking via Unvalidated Miner List Manipulation in NextRound Transition

## Summary
The AEDPoS consensus validation logic fails to verify that the miner list in a NextRound transition matches the expected miner list from the current round. This allows any legitimate miner to inject arbitrary public keys during their NextRound block, permanently replacing all consensus participants and achieving complete blockchain takeover.

## Finding Description

The vulnerability exists in the consensus validation pipeline that processes NextRound transitions. The core issue is that **no validator checks whether the miner public keys (dictionary keys of `RealTimeMinersInformation`) in the provided next round match those in the current round**.

**Validation Gap:**

The `ValidationForNextRound()` method only validates that the round number increments by one and all `InValue` fields are null [1](#0-0) , but never validates the miner list.

**Complete Validation Pipeline for NextRound:**

The validation providers instantiated for NextRound behavior are defined in the validation setup [2](#0-1) :

1. **MiningPermissionValidationProvider** - checks if sender is in the **base round** (current round from state), not the provided round [3](#0-2) 

2. **NextRoundMiningOrderValidationProvider** - validates internal consistency within the provided round only [4](#0-3) 

**None of these validators compare the miner list in the provided next round against the current round.**

**Attack Execution:**

The public `NextRound` method accepts arbitrary `NextRoundInput` and processes it [5](#0-4) . After passing validation, `ProcessNextRound()` converts the input to a Round object and directly stores the attacker-provided round [6](#0-5) . 

The malicious round is stored without any miner list validation [7](#0-6) , and the current round number is updated [8](#0-7) .

**Permanent Enforcement:**

All future mining permission checks retrieve the round from state and verify against stored miner lists [9](#0-8) , making the takeover permanent.

**Legitimate Behavior Comparison:**

The legitimate `GenerateNextRoundInformation()` method preserves the current round's miner list by iterating over existing miners from `RealTimeMinersInformation` [10](#0-9) . This method is called during legitimate consensus block production [11](#0-10) . However, validation does not enforce this invariant.

**Post-Execution Validation Cannot Detect:**

Post-execution validation compares the header information with state **after** the malicious round has already been stored [12](#0-11) . Since both the header and state contain the same malicious round after execution (line 87), the hash comparison at lines 100-101 passes, and the miner replacement check at lines 103-123 is never executed.

## Impact Explanation

**Critical Consensus Integrity Violation:**

- An attacker can permanently replace the entire miner list with arbitrary public keys of their choosing
- The malicious miner list becomes the authoritative source for all future mining permission checks
- All legitimate miners are immediately and permanently locked out of consensus participation
- The attacker's chosen addresses gain exclusive control over block production
- The chain continues operating but under complete attacker control with no decentralization
- No automatic recovery mechanism exists in the protocol

**Blockchain-Wide Impact:**

- Complete loss of consensus security and decentralization
- Attacker can censor any transactions indefinitely
- Attacker controls all governance actions that require block production
- The blockchain becomes a centralized system controlled by the attacker
- Recovery would require hard fork or manual intervention
- All users, applications, and dependent systems are affected

This represents a **CRITICAL** severity issue as it allows complete and irreversible takeover of the blockchain's consensus mechanism.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a legitimate miner in the current round (achievable through normal election/staking process)
- Must produce a block during their designated NextRound time slot
- No additional permissions, stake requirements, or resources needed

**Attack Complexity:**
- **Very Low** - Attacker simply constructs a `NextRoundInput` with arbitrary miner public keys in `RealTimeMinersInformation` using the public input structure [13](#0-12) 
- Single transaction through the public `NextRound` method [5](#0-4) 
- No timing constraints or race conditions
- No need for coordination with other actors
- 100% success rate once validation is bypassed

**Feasibility:**
- **HIGH** - Miners rotate through NextRound responsibilities in every term
- Each miner gets multiple opportunities to execute the attack
- No detection mechanisms exist before commitment
- No economic barriers beyond being a current miner

## Recommendation

Add a validation provider that explicitly checks miner list consistency during NextRound transitions. The validator should verify that the set of public keys in `RealTimeMinersInformation` of the provided next round exactly matches those in the current round.

Recommended fix in `RoundTerminateValidationProvider.ValidationForNextRound()`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // NEW: Validate miner list consistency
    var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    var nextMiners = extraData.Round.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    if (baseMiners.Count != nextMiners.Count || !baseMiners.SequenceEqual(nextMiners))
        return new ValidationResult { Message = "Miner list in next round does not match current round." };

    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

This ensures that only NextTerm transitions (which have their own validation) can modify the miner list, while NextRound transitions maintain consensus participant consistency as intended by the protocol design.

## Proof of Concept

The vulnerability can be demonstrated by constructing a test that:
1. Initializes a consensus contract with legitimate miners
2. Has one legitimate miner create a `NextRoundInput` with completely different miner public keys
3. Calls `NextRound()` with this malicious input
4. Verifies that the transaction succeeds and the malicious miner list is stored
5. Confirms that subsequent mining permission checks use the malicious list

The test would show that all pre-execution and post-execution validations pass despite the miner list being completely replaced, confirming the validation gap.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L91-97)
```csharp
    private bool TryToUpdateRoundNumber(long roundNumber)
    {
        var oldRoundNumber = State.CurrentRoundNumber.Value;
        if (roundNumber != 1 && oldRoundNumber + 1 != roundNumber) return false;
        State.CurrentRoundNumber.Value = roundNumber;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-56)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L5-40)
```csharp
public partial class NextRoundInput
{
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }

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
