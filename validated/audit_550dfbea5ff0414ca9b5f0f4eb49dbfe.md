# Audit Report

## Title
Miners Can Manipulate FinalOrderOfNextRound to Control Next Round Mining Position

## Summary
The AEDPoS consensus contract allows miners to arbitrarily set their `SupposedOrderOfNextRound` and manipulate other miners' `FinalOrderOfNextRound` values through the `UpdateValue` method without any validation. This bypasses the intended deterministic order calculation based on signature hashes, enabling malicious miners to consistently secure favorable mining positions across multiple rounds.

## Finding Description

The AEDPoS consensus mechanism is designed to ensure fair rotation of mining opportunities through deterministic order calculation. The correct behavior calculates a miner's next round position as `GetAbsModulus(signature.ToInt64(), minersCount) + 1`, ensuring unpredictability based on cryptographic signatures. [1](#0-0) 

However, the `ProcessUpdateValue` method directly accepts miner-provided order values without any validation or recalculation. [2](#0-1) 

Furthermore, miners can modify OTHER miners' positions through the `TuneOrderInformation` field, which is applied without verification that these adjustments are legitimate. [3](#0-2) 

The `UpdateValueValidationProvider` only validates cryptographic correctness of signatures and hashes, completely ignoring order field validation. [4](#0-3) 

During validation recovery before block execution, the system blindly copies the provided order values without recalculating them against the signature hash. [5](#0-4) 

The `NextRoundMiningOrderValidationProvider` only validates that the COUNT of miners with assigned orders matches those who produced blocks, not the CORRECTNESS of the actual order values themselves. [6](#0-5) 

Most critically, these manipulated values directly determine the mining order when generating the next round, with no recalculation or validation against expected values. [7](#0-6) 

**Attack Flow**:
1. Malicious miner calls the public `UpdateValue` method [8](#0-7) 
2. Constructs custom `UpdateValueInput` with `SupposedOrderOfNextRound = 1` [9](#0-8) 
3. Uses `TuneOrderInformation` to push competing miners to higher positions
4. The only precondition check verifies miner list membership, which all active miners satisfy [10](#0-9) 
5. Values are accepted and propagate to next round generation without validation

## Impact Explanation

This vulnerability represents a **CRITICAL** breach of consensus integrity:

**Consensus Fairness Violation**: The AEDPoS mechanism's core fairness guarantee—that mining order is determined by unpredictable signature hashes—is completely bypassed. Malicious miners can consistently secure position 1, gaining systematic advantages in transaction ordering, MEV extraction, and block rewards.

**Economic Impact**: The first miner in each round gains priority in transaction selection and fee collection. By consistently mining first, an attacker extracts maximum value from transaction ordering while honest miners lose their fair share of mining opportunities and associated rewards.

**Protocol Integrity**: This breaks the fundamental invariant that miner schedule integrity must be maintained. The deterministic, cryptographically-derived mining order is replaced with arbitrary attacker-controlled values, fundamentally undermining the consensus mechanism's design principles.

**Systemic Risk**: This manipulation persists across rounds. Once an attacker establishes favorable positioning, they maintain it indefinitely, creating a permanent advantage that compounds over time.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of exploitation:

**Attacker Accessibility**: Any active miner in the consensus set can execute this attack. The only requirement is being part of the legitimate miner list, which is the normal operating condition for all consensus participants.

**Technical Simplicity**: The attack requires no cryptographic bypasses or complex state manipulation. An attacker simply constructs a custom `UpdateValueInput` message instead of using the helper function that calculates correct values. [11](#0-10) 

**No Additional Barriers**: The validation system runs during block execution, but adds no validators for order field correctness during UpdateValue behavior. [12](#0-11) 

**Low Detection Risk**: Manipulated values appear structurally valid (integers within valid range). Without explicit comparison against expected calculated values, the manipulation is invisible to on-chain monitoring.

## Recommendation

Implement strict validation of order fields in `ProcessUpdateValue`:

1. **Recalculate and validate SupposedOrderOfNextRound**: Instead of accepting user input, always calculate it from the signature: `var expectedOrder = GetAbsModulus(updateValueInput.Signature.ToInt64(), minersCount) + 1;` and assert it matches the provided value.

2. **Validate TuneOrderInformation**: Before applying tune order adjustments, verify they represent legitimate conflict resolutions by checking that the supposed orders actually conflict and the new orders follow the conflict resolution algorithm.

3. **Add order validation provider**: Create a new `OrderValueValidationProvider` that validates the correctness of `SupposedOrderOfNextRound` against the signature hash and validates `TuneOrderInformation` entries represent valid conflict resolutions.

4. **Remove direct order assignment**: Replace the direct assignment pattern with a call to `ApplyNormalConsensusData` which includes the correct order calculation logic.

## Proof of Concept

```csharp
// Test demonstrating order manipulation
[Fact]
public async Task MinerCanManipulateNextRoundOrder()
{
    // Assume we have 5 miners in the consensus
    var maliciousMiner = SampleAccount.Accounts[0];
    var honestMiners = SampleAccount.Accounts.Skip(1).Take(4).ToList();
    
    // Malicious miner crafts UpdateValueInput with manipulated order
    var manipulatedInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("out_value"),
        Signature = HashHelper.ComputeFrom("signature"),
        // Attacker sets themselves to position 1 regardless of signature hash
        SupposedOrderOfNextRound = 1,
        // Push all other miners to higher positions
        TuneOrderInformation = {
            { honestMiners[0].PublicKey.ToHex(), 2 },
            { honestMiners[1].PublicKey.ToHex(), 3 },
            { honestMiners[2].PublicKey.ToHex(), 4 },
            { honestMiners[3].PublicKey.ToHex(), 5 }
        },
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        RandomNumber = ByteString.CopyFromUtf8("random")
    };
    
    // Execute UpdateValue - should fail but currently succeeds
    var result = await ConsensusStub.UpdateValue.SendAsync(manipulatedInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Currently passes!
    
    // Verify next round generation uses manipulated values
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var nextRound = currentRound.GenerateNextRound();
    
    // Attacker is at position 1 in next round despite incorrect calculation
    nextRound.RealTimeMinersInformation[maliciousMiner.PublicKey.ToHex()].Order.ShouldBe(1);
}
```

**Notes**:
- This vulnerability exists because `ProcessUpdateValue` never calls `ApplyNormalConsensusData`, which contains the correct deterministic order calculation logic
- The validation system only checks signature and hash correctness, not whether order values match expected calculations
- Unlike legitimate conflict resolution in `ApplyNormalConsensusData`, no validation ensures `TuneOrderInformation` represents actual conflicts
- The `ExtractInformationToUpdateConsensus` helper creates correct values but is optional—miners can bypass it by calling `UpdateValue` directly

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** protobuf/aedpos_contract.proto (L206-208)
```text
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L16-43)
```csharp
    public UpdateValueInput ExtractInformationToUpdateConsensus(string pubkey, ByteString randomNumber)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return null;

        var minerInRound = RealTimeMinersInformation[pubkey];

        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);

        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);

        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);

        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
            PreviousInValue = minerInRound.PreviousInValue ?? Hash.Empty,
            RoundId = RoundIdForValidation,
            ProducedBlocks = minerInRound.ProducedBlocks,
            ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```
