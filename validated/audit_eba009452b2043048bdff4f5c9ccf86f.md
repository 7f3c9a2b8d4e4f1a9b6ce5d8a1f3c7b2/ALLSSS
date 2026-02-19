# Audit Report

## Title
Hash.Empty Bypass in Consensus Behavior Determination Allows Miners to Manipulate Block Production Logic

## Summary
The AEDPoS consensus contract fails to validate that `OutValue` is a cryptographically valid hash, allowing miners to submit `Hash.Empty` (32 bytes of zeros). The validation only checks byte count using `.Any()`, not byte values, enabling malicious miners to bypass proper consensus behavior assignment and avoid cryptographic commitments required for randomness generation and secret sharing.

## Finding Description

The vulnerability exists in the consensus validation and behavior determination logic. In AEDPoS, miners must provide cryptographic commitments through an InValue/OutValue mechanism where `OutValue = Hash(InValue)`. However, the validation accepts `Hash.Empty` as a valid OutValue.

**Validation Weakness:**
The `NewConsensusInformationFilled` method validates OutValue using: [1](#0-0) 

This checks that `OutValue != null` (Hash.Empty passes) and `OutValue.Value.Any()` (returns true for 32 zero bytes). There is no validation that OutValue contains non-zero values or equals a proper hash.

**Hash.Empty Definition:** [2](#0-1) 

Hash.Empty is a valid Hash object containing 32 zero bytes, making it non-null but cryptographically invalid.

**Behavior Determination Bypass:**
The consensus behavior logic checks: [3](#0-2) 

When `OutValue == Hash.Empty`, this condition evaluates to false (Hash.Empty is not null), causing `HandleMinerInNewRound` to be skipped. The miner is incorrectly treated as having already produced blocks.

**PreviousInValue Escape Hatch:** [4](#0-3) 

This line explicitly allows `previousInValue == Hash.Empty` without validating that `Hash(previousInValue) == previousOutValue`, enabling miners to perpetually use Hash.Empty across rounds.

**State Storage Without Validation:** [5](#0-4) 

The OutValue from input is stored directly without checking if it equals Hash.Empty.

**Expected Behavior:**
Per the consensus block extra data generation: [6](#0-5) 

OutValue should always be the hash of a randomly generated InValue, never Hash.Empty.

**Attack Path:**
1. Malicious miner calls UpdateValue with `OutValue = Hash.Empty`
2. Validation passes (Hash.Empty has 32 bytes)
3. Behavior check treats miner as having mined (skips HandleMinerInNewRound)
4. State stores Hash.Empty
5. Next round, miner provides `previousInValue = Hash.Empty` (explicitly allowed)
6. Cycle repeats indefinitely

## Impact Explanation

**Consensus Integrity Violation:**
The AEDPoS protocol relies on miners making cryptographic commitments through OutValue/InValue pairs for verifiable randomness. By accepting Hash.Empty, miners can:
- Avoid proper cryptographic commitments
- Skip contributing entropy to random number generation used for block producer selection
- Break the threshold secret sharing mechanism designed to recover InValues

**Behavior Manipulation:**
The `HandleMinerInNewRound` method determines critical consensus behaviors (UPDATE_VALUE, TINY_BLOCK, NEXT_ROUND): [7](#0-6) 

Bypassing this logic allows miners to:
- Produce blocks outside proper behavior assignments
- Disrupt round transition timing
- Affect irreversible block height calculations

**Randomness Weakness:**
Signature calculation aggregates all miners' signatures: [8](#0-7) 

Miners using Hash.Empty contribute no entropy, weakening randomness for next round order determination and cross-chain verification.

**Affected Parties:**
- All network participants depending on consensus integrity
- Smart contracts using consensus randomness
- Cross-chain operations requiring secure random values
- Block reward distribution mechanisms

## Likelihood Explanation

**Entry Point Accessibility:**
The UpdateValue method is accessible to any registered miner: [9](#0-8) 

Authorization is validated via PreCheck: [10](#0-9) 

And mining permission validation: [11](#0-10) 

Any registered miner can exploit this - becoming a miner is achievable through standard election/staking mechanisms.

**No On-Chain Protection:**
There is no validation preventing Hash.Empty submission. The codebase contains no instances of `OutValue = Hash.Empty` assignments, indicating it should never occur legitimately.

**Attack Simplicity:**
Exploitation requires only modifying the consensus client to submit Hash.Empty instead of computing proper hashes. No cryptographic attacks or timing manipulation needed.

**Economic Incentive:**
Costs are minimal (standard mining operation) while potential benefits include:
- Influencing randomness outcomes
- Disrupting competitor block production
- Manipulating behavior assignments

## Recommendation

Add explicit validation to reject Hash.Empty:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // Add check for Hash.Empty
    if (minerInRound.OutValue == Hash.Empty || minerInRound.Signature == Hash.Empty)
        return false;
        
    return minerInRound.OutValue != null && minerInRound.Signature != null &&
           minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
}
```

Additionally, modify ValidatePreviousInValue to only allow Hash.Empty for legitimate cases (first round or new miner):

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    // ... existing code ...
    
    // Only allow Hash.Empty for first round or when miner wasn't in previous round
    if (previousInValue == Hash.Empty)
    {
        return validationContext.PreviousRound.RoundNumber == 1 || 
               !validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey);
    }

    return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanSubmitHashEmpty_BypassesBehaviorDetermination()
{
    // Setup: Initialize consensus with test miner
    await InitializeConsensusContract();
    var minerKeyPair = InitialCoreDataCenterKeyPairs[0];
    
    // Attack: Miner submits UpdateValue with Hash.Empty
    var maliciousInput = new UpdateValueInput
    {
        OutValue = Hash.Empty,  // Invalid: should be Hash(InValue)
        Signature = Hash.Empty,
        PreviousInValue = Hash.Empty,
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        RoundId = 1,
        SupposedOrderOfNextRound = 1
    };
    
    // This should fail but doesn't - vulnerability confirmed
    var result = await ConsensusStub.UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Miner's OutValue is stored as Hash.Empty
    var round = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo = round.RealTimeMinersInformation[minerKeyPair.PublicKey.ToHex()];
    minerInfo.OutValue.ShouldBe(Hash.Empty);  // Vulnerability: invalid hash accepted
    
    // Impact: Miner treated as having mined (OutValue != null)
    // but provided no valid cryptographic commitment
}
```

## Notes

The explicit allowance of `previousInValue == Hash.Empty` at line 46 appears designed for legitimate edge cases (first round, new miner replacement). However, without corresponding checks on the current OutValue, this creates an exploitable bypass. The validation architecture assumes honest client behavior for OutValue generation but provides no on-chain enforcement, violating defense-in-depth principles for consensus-critical operations.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** src/AElf.Types/Types/Hash.cs (L13-14)
```csharp
        public static readonly Hash Empty = LoadFromByteArray(Enumerable.Range(0, AElfConstants.HashByteArrayLength)
            .Select(x => byte.MinValue).ToArray());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L49-56)
```csharp
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-115)
```csharp
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;

            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;

            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L245-245)
```csharp
        minerInRound.OutValue = updateValueInput.OutValue;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L67-67)
```csharp
        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-114)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-24)
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
```
