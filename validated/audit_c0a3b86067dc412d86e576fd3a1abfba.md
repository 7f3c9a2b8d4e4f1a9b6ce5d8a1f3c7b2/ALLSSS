# Audit Report

## Title
Continuous Block Limit Bypass via Public Key Replacement

## Summary
A miner can bypass the AEDPoS consensus continuous block production limit (8 blocks) by strategically replacing their public key. The `RecordCandidateReplacement` method updates round information but fails to update `State.LatestPubkeyToTinyBlocksCount`, causing validation checks to be skipped and the block counter to reset instead of decrement. This allows a malicious miner to produce significantly more continuous blocks than intended by using a series of fresh keypairs.

## Finding Description

The vulnerability exists in the interaction between three key components of the AEDPoS consensus mechanism:

**1. Entry Point - Key Replacement**

The `ReplaceCandidatePubkey` method allows any candidate admin to replace their public key [1](#0-0) . This method calls `RecordCandidateReplacement` in the consensus contract [2](#0-1) .

**2. Core Issue - Missing State Update**

The `RecordCandidateReplacement` method updates the round's `RealTimeMinersInformation` by replacing the old pubkey with the new one [3](#0-2) , but critically **does NOT update** `State.LatestPubkeyToTinyBlocksCount`. After this method executes, `State.LatestPubkeyToTinyBlocksCount` still references the old public key, while the miner's identity in the current round has been updated to the new key.

**3. Validation Bypass**

The `ContinuousBlocksValidationProvider` checks if a miner has exceeded the continuous block limit by comparing the stored pubkey with the current block producer's pubkey [4](#0-3) . When the pubkeys don't match (old key in state vs. new key producing block), the `BlocksCount < 0` check is skipped, allowing the miner to bypass the limit.

**4. Counter Reset Instead of Decrement**

After validation, `ResetLatestProviderToTinyBlocksCount` is called during consensus processing [5](#0-4) . When the stored pubkey doesn't match the current block producer, the else branch executes, resetting the counter to `minersCountInTheory.Sub(1)` (typically 7) instead of decrementing it. This gives the miner a fresh counter.

**5. Maximum Block Limit**

The continuous block limit is defined as 8 blocks [6](#0-5) .

**Attack Flow:**
1. Miner produces blocks with key_1, counter decrements: 7→6→5...→1
2. Before reaching 0, call `ReplaceCandidatePubkey(key_1, key_2)`
3. Produce next block with key_2: validation bypassed, counter resets to 7
4. Repeat with key_3, key_4, etc.

**Constraints Verified:**
- Old keys are banned after replacement (preventing reuse) [7](#0-6) 
- No rate limiting or cooldown on replacements exists in the codebase
- Fresh keys are unlimited and unbanned

## Impact Explanation

**Consensus Integrity Violation**: The continuous block limit exists to prevent centralization and ensure fair block production rotation among miners. By bypassing this limit, the vulnerability breaks a core consensus security guarantee.

**Quantified Impact**:
- Normal limit: 8 continuous blocks per miner
- With N prepared keypairs: attacker can produce approximately 8 + 7*(N-1) continuous blocks
- Example: 10 keypairs = ~71 continuous blocks vs. intended 8 blocks (787% increase)

**Concrete Harms**:
1. **Unfair Mining Advantage**: Attacker gains disproportionate block production opportunities
2. **Reward Misallocation**: More blocks = more mining rewards, directly extracting value from honest miners
3. **Centralization Risk**: Single miner can dominate block production, defeating the decentralization purpose of the limit
4. **Network Security Degradation**: The continuous block limit was designed to reduce fork risks and improve network resilience

**Affected Parties**: All honest miners suffer reduced mining opportunities and rewards. The entire network's decentralization and consensus security guarantees are weakened.

## Likelihood Explanation

**Reachable Entry Point**: `ReplaceCandidatePubkey` is a public method requiring only candidate admin authorization. Every miner controls their own candidate admin by default, making this a standard permission [8](#0-7) .

**Attacker Requirements**:
- Control of a candidate admin address (standard for any participating miner)
- Preparation of multiple fresh keypairs (cryptographically trivial, zero marginal cost)
- Timing of replacements during their mining time slots (straightforward with known consensus schedule)

**Execution Feasibility**:
- No technical barriers beyond standard miner capabilities
- No rate limiting or protective constraints in the code
- Replacements are legitimate operations that may not trigger immediate scrutiny
- Economic incentive is clear: additional block rewards

**Detection Difficulty**: While replacements are on-chain events (`CandidatePubkeyReplaced`) [9](#0-8) , they are designed as legitimate maintenance operations. Multiple rapid replacements might appear suspicious but could be attributed to security key rotation.

**Probability Assessment**: Medium-High likelihood. The attack is technically straightforward with clear financial incentive (additional mining rewards), but requires premeditation and preparation of multiple keypairs.

## Recommendation

Add the following state update to the `RecordCandidateReplacement` method in `AEDPoSContract.cs` after updating the round information:

```csharp
// Update LatestPubkeyToTinyBlocksCount if it references the old pubkey
var latestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value;
if (latestPubkeyToTinyBlocksCount != null && 
    latestPubkeyToTinyBlocksCount.Pubkey == input.OldPubkey)
{
    State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
    {
        Pubkey = input.NewPubkey,
        BlocksCount = latestPubkeyToTinyBlocksCount.BlocksCount
    };
}
```

This ensures that the continuous block counter correctly tracks the miner's identity even after key replacement, preventing the validation bypass.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a miner with key_1 that produces blocks until `LatestPubkeyToTinyBlocksCount.BlocksCount` reaches 1
2. Calling `ReplaceCandidatePubkey(key_1, key_2)` through the candidate admin
3. Producing the next block with key_2
4. Verifying that `LatestPubkeyToTinyBlocksCount.BlocksCount` has reset to 7 instead of continuing to decrement
5. Observing that the miner can now produce 7 more blocks with key_2 before hitting the limit
6. Repeating the process with key_3, key_4, etc. to produce far more than 8 continuous blocks

The test would verify that after each replacement, the counter resets to `minersCountInTheory - 1` instead of maintaining the decremented value, allowing the attacker to exceed the 8-block limit through the desynchronization between round information and the continuous block counter state.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L245-246)
```csharp
        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L250-254)
```csharp
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

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

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
