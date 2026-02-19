### Title
Consensus Hijacking via Unvalidated Miner List Manipulation in NextRound Transition

### Summary
The `ValidationForNextRound()` function in `RoundTerminateValidationProvider` fails to validate that the miner list in the provided next round matches the expected miner list from the current round. This allows any legitimate miner to replace the entire miner list with arbitrary public keys during a NextRound transition, completely hijacking the consensus protocol. The malicious round is then stored in state and enforced for all subsequent mining permission checks.

### Finding Description

**Root Cause:**

The validation logic in `ValidationForNextRound()` only checks two conditions:
1. Round number is incremented correctly (current + 1)
2. All miners have null `InValue` fields [1](#0-0) 

Critically, there is **no validation** that the miner public keys in `extraData.Round.RealTimeMinersInformation` (the dictionary keys) match the expected miner list from the current round.

**Exploitation Path:**

1. When a NextRound block is produced, the validation flow includes multiple providers but none verify miner list consistency: [2](#0-1) 

2. The `MiningPermissionValidationProvider` only checks if the **sender** is in the **base round** (current round from state), not whether the provided next round has correct miners: [3](#0-2) 

3. The `NextRoundMiningOrderValidationProvider` only validates internal consistency within the provided round, not against the base round: [4](#0-3) 

4. After passing validation, `ProcessNextRound()` directly stores the attacker-provided round without any miner list verification: [5](#0-4) 

5. The malicious round is stored via `AddRoundInformation()` which performs no validation: [6](#0-5) 

6. Future mining permission checks use this stored malicious round, locking out legitimate miners: [7](#0-6) 

**Why Legitimate Generation is Different:**

The legitimate `GenerateNextRoundInformation()` preserves the current round's miner list: [8](#0-7) 

It iterates over `RealTimeMinersInformation` from the current round and creates entries with the **same public keys** in the next round. However, validation does not enforce this invariant.

### Impact Explanation

**Consensus Integrity Destruction:**
- An attacker can inject arbitrary miner public keys into the next round, replacing all legitimate miners
- The malicious miner list is permanently stored in `State.Rounds[roundNumber]`
- All future blocks must be produced by the attacker's chosen miners, as `MiningPermissionValidationProvider` enforces the stored miner list
- Legitimate miners are completely locked out of the consensus

**Protocol-Wide Consequences:**
- Complete loss of decentralization and security
- Attacker controls all block production and can censor transactions indefinitely
- Chain continues operating but under full attacker control
- No automatic recovery mechanism exists
- Affects the entire blockchain, not just individual transactions

**Severity Justification:**
This is **CRITICAL** because it allows complete and permanent consensus takeover with no fund requirements beyond being a current miner. The attacker gains absolute control over the blockchain.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a legitimate miner in the current round
- Must produce a block during their designated NextRound time slot
- No special permissions, stake, or economic resources required beyond existing miner status

**Attack Complexity:**
- **Low complexity**: Attacker simply provides a malicious `NextRoundInput` with different miner public keys
- No timing windows or race conditions to exploit
- Single transaction execution achieves full compromise
- No need to coordinate multiple transactions or actors

**Feasibility Conditions:**
- Attack is **always feasible** when it's the attacker's turn to produce the NextRound block
- In AEDPoS, miners rotate through NextRound responsibilities, so opportunity arises regularly
- No detection mechanisms exist before the malicious round is committed

**Detection Constraints:**
- Post-execution validation (`ValidateConsensusAfterExecution`) compares stored round with header round, but they're identical (both malicious): [9](#0-8) 

- No alerts or safeguards trigger on miner list changes during NextRound

**Probability:**
- **HIGH**: Any miner can exploit this during their NextRound slot (occurs every term/multiple rounds)
- No economic barriers or technical obstacles prevent execution
- Attack succeeds with 100% reliability if validation is bypassed

### Recommendation

**Immediate Fix - Add Miner List Validation:**

In `RoundTerminateValidationProvider.ValidationForNextRound()`, add validation that the next round's miner list matches the current round's miner list:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing round number check
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // NEW: Validate miner list consistency (unless miner list is expected to change)
    if (!extraData.Round.IsMinerListJustChanged)
    {
        var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var providedMiners = extraData.Round.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        
        if (baseMiners.Count != providedMiners.Count || 
            !baseMiners.SequenceEqual(providedMiners))
        {
            return new ValidationResult { 
                Message = "Next round miner list does not match current round. Unauthorized miner list manipulation detected." 
            };
        }
    }

    // Existing InValue check
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

**Additional Hardening:**

1. For `NextTerm` transitions where miner list changes are legitimate, validate against the Election Contract's official miner list
2. Add state comparison in `ValidateConsensusAfterExecution` to detect unexpected miner list changes
3. Implement monitoring/alerts for miner list modifications
4. Add regression tests covering miner list manipulation scenarios

### Proof of Concept

**Initial State:**
- Current round N with legitimate miners: `[MinerA, MinerB, MinerC]`
- MinerA is the designated extra block producer for round N (triggers NextRound)
- All miners have completed their time slots

**Attack Sequence:**

1. **MinerA (Attacker) generates malicious NextRound block:**
   - Creates `NextRoundInput` with `Round.RealTimeMinersInformation` containing: `[AttackerMiner1, AttackerMiner2, AttackerMiner3]`
   - Round number set to `N + 1`
   - All `InValue` fields set to `null`
   - Sets internal consistency (FinalOrderOfNextRound matching OutValue presence)

2. **Validation executes (`ValidateBeforeExecution`):**
   - ✓ `MiningPermissionValidationProvider`: MinerA is in base round N - **PASS**
   - ✓ `TimeSlotValidationProvider`: Correct timing - **PASS**
   - ✓ `ContinuousBlocksValidationProvider`: Not excessive blocks - **PASS**
   - ✓ `NextRoundMiningOrderValidationProvider`: Internal consistency maintained - **PASS**
   - ✓ `RoundTerminateValidationProvider`: Round number is N+1, all InValues null - **PASS**

3. **Processing executes (`ProcessNextRound`):**
   - Malicious round stored: `State.Rounds[N+1] = attackerProvidedRound`
   - Contains `RealTimeMinersInformation = {AttackerMiner1, AttackerMiner2, AttackerMiner3}`

4. **Post-validation (`ValidateConsensusAfterExecution`):**
   - Retrieves `State.Rounds[N+1]` (the just-stored malicious round)
   - Compares with header round (same malicious round)
   - ✓ Hashes match - **PASS**

**Actual Result:**
- Round N+1 now enforces attacker's miner list
- `State.Rounds[N+1].RealTimeMinersInformation.Keys = [AttackerMiner1, AttackerMiner2, AttackerMiner3]`
- Legitimate miners (MinerA, MinerB, MinerC) can no longer produce blocks
- Only attacker-controlled miners can continue the chain

**Expected Result:**
- Validation should **reject** the block with error: "Next round miner list does not match current round"
- Round N+1 should never be stored with manipulated miner list
- Legitimate miners maintain consensus control

**Success Condition:**
The attack succeeds if `State.Rounds[N+1]` contains the attacker's chosen miners instead of the legitimate current round miners.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-36)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-127)
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
```
