### Title
Missing Duplicate UpdateValue Check Allows Consensus Data Overwrite Within Same Round

### Summary
The AEDPoS consensus contract lacks validation to prevent a miner from calling `UpdateValue` multiple times within the same round. The validation logic calls `RecoverFromUpdateValue` before checking if `OutValue` is already set in state, allowing a malicious miner to overwrite their previously submitted consensus data. This enables manipulation of consensus randomness and next-round ordering.

### Finding Description

The vulnerability exists in the consensus validation flow where miners can submit multiple `UpdateValue` transactions for the same pubkey within a single round, with each subsequent submission overwriting previous values.

**Root Cause:**

In the validation flow, `RecoverFromUpdateValue` is called on the `baseRound` (current state) BEFORE any duplicate-check validation occurs: [1](#0-0) 

This method unconditionally overwrites the `OutValue` and `Signature` fields in the baseRound with values from the provided round: [2](#0-1) 

The modified baseRound is then used to construct the validation context: [3](#0-2) 

The `UpdateValueValidationProvider` only checks that the provided values are non-null, not whether values were already set in the original state: [4](#0-3) 

When the transaction executes, `ProcessUpdateValue` unconditionally overwrites the stored values: [5](#0-4) 

**Why Existing Protections Fail:**

1. `EnsureTransactionOnlyExecutedOnceInOneBlock` only prevents multiple consensus transactions in the SAME block, not across different blocks in the same round: [6](#0-5) 

2. The consensus behavior provider prevents GENERATING additional UpdateValue commands after OutValue is set, but cannot prevent manually crafted transactions: [7](#0-6) 

3. Time slot validation only checks if the miner is within their time slot, not if they've already updated: [8](#0-7) 

4. Permission validation only checks if the signer is in the miner list: [9](#0-8) 

### Impact Explanation

**Consensus Randomness Manipulation:**
The `Signature` field is directly used to generate random hashes for the blockchain: [10](#0-9) 

A malicious miner can submit multiple UpdateValue transactions with different `InValue` inputs to generate different signatures, effectively "re-rolling" the random output until they obtain a favorable result for validator selection, reward distribution, or any protocol mechanism relying on this randomness.

**Next Round Order Manipulation:**
The signature determines the miner's order in the next round: [11](#0-10) 

By manipulating their signature, a malicious miner can control their position in the next round, potentially gaining first-mover advantages or avoiding unfavorable positions.

**Secret Sharing Integrity Breach:**
If secret sharing is enabled, the attacker can manipulate revealed in-values and encrypted pieces: [12](#0-11) 

This could break the cryptographic guarantees of the secret sharing mechanism and compromise consensus integrity.

**Severity: HIGH** - Breaks fundamental consensus invariants including randomness integrity and fair miner ordering.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a legitimate miner with an allocated time slot in the current round
- Can sign transactions with their miner key
- Can submit transactions directly to the network

**Attack Complexity: LOW**
1. Miner produces their first block at time T with `UpdateValue` containing `OutValue_1 = Hash(InValue_1)`
2. Within the same time slot (before T + mining_interval), miner produces another block at T+Δ with `UpdateValue` containing `OutValue_2 = Hash(InValue_2)` where `InValue_2 ≠ InValue_1`
3. Second transaction passes all validations and overwrites the first submission

**Feasibility Conditions:**
- Mining interval provides sufficient time for multiple blocks (typically 4-8 seconds)
- No additional infrastructure required beyond standard miner capabilities
- Attack leaves clear on-chain evidence but no automatic detection/prevention exists

**Detection Constraints:**
Off-chain monitoring could detect multiple UpdateValue calls from the same miner in one round, but no on-chain prevention exists. The attack is profitable if the gained advantage (favorable randomness, better round position) exceeds the reputational cost.

**Probability: HIGH** - Any malicious miner can execute this attack without special circumstances or race conditions.

### Recommendation

Add an explicit check in `ValidateBeforeExecution` BEFORE calling `RecoverFromUpdateValue` to verify that the miner has not already submitted consensus data in the current round:

```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    var pubkey = extraData.SenderPubkey.ToHex();
    if (baseRound.RealTimeMinersInformation.ContainsKey(pubkey))
    {
        var minerInRound = baseRound.RealTimeMinersInformation[pubkey];
        Assert(minerInRound.OutValue == null || minerInRound.OutValue.Value.IsEmpty, 
               "Miner has already submitted consensus data in this round.");
    }
    baseRound.RecoverFromUpdateValue(extraData.Round, pubkey);
}
```

**Invariant to Enforce:**
Each miner can call `UpdateValue` at most once per round, verified by checking that `OutValue` is null/empty in state before accepting a new submission.

**Test Cases:**
1. Verify that a second UpdateValue transaction from the same miner in the same round is rejected
2. Verify that UpdateValue in a new round is accepted even if the miner updated in the previous round
3. Verify that TinyBlock transactions are still allowed after UpdateValue in the same time slot

### Proof of Concept

**Initial State:**
- Current round number: 100
- Miner M has time slot: [1000s, 1008s] (8-second mining interval)
- Miner M's OutValue in round 100: null (hasn't mined yet)

**Attack Steps:**

**Step 1** (at timestamp 1000s):
- Miner M produces block at height H
- Block contains UpdateValue transaction with:
  - OutValue_A = Hash(InValue_A)  
  - Signature_A = CalculateSignature(InValue_A)
- Validation: PASS (first update, OutValue was null)
- Execution: Sets M's OutValue = OutValue_A, Signature = Signature_A in state
- Random hash generated: RandomHash_A (used for consensus)

**Step 2** (at timestamp 1004s, still within [1000s, 1008s]):
- Miner M produces another block at height H+1
- Block contains UpdateValue transaction with:
  - OutValue_B = Hash(InValue_B) where InValue_B ≠ InValue_A
  - Signature_B = CalculateSignature(InValue_B) where Signature_B ≠ Signature_A
- Validation checks:
  - `EnsureTransactionOnlyExecutedOnceInOneBlock`: PASS (different block)
  - `PreCheck`: PASS (M is valid miner)
  - `RecoverFromUpdateValue`: Overwrites OutValue_A with OutValue_B in baseRound
  - `TimeSlotValidationProvider`: PASS (1004s within [1000s, 1008s])
  - `UpdateValueValidationProvider`: PASS (OutValue_B is non-null)
- Execution: Sets M's OutValue = OutValue_B, Signature = Signature_B in state
- Random hash generated: RandomHash_B (OVERWRITES RandomHash_A)

**Expected Result:** Second UpdateValue transaction rejected with "Already submitted consensus data"

**Actual Result:** Second UpdateValue transaction succeeds, overwriting OutValue_A/Signature_A with OutValue_B/Signature_B

**Success Condition:** Query `State.Rounds[100].RealTimeMinersInformation[M].OutValue` returns OutValue_B instead of OutValue_A, demonstrating successful overwrite.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L14-20)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-248)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-44)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```
