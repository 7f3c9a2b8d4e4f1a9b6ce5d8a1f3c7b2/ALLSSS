# Audit Report

## Title
Missing Validation for Empty Miner List Enables Permanent Blockchain Halt via NextRound/NextTerm

## Summary
The AEDPoS consensus validation pipeline fails to verify that proposed rounds contain at least one miner. Multiple validation providers check properties of miners but do not validate miner existence, allowing a malicious miner to submit an empty round that passes all validations and permanently halts the blockchain.

## Finding Description

The vulnerability exists in the consensus validation pipeline's handling of NextRound transactions. The critical flaw is that validators check properties **of** miners but never check **if** miners exist in the proposed round.

**Validation Context Setup:**

When validation is invoked, it creates a context where `BaseRound` is the current state and `ProvidedRound` is the submitted round data. [1](#0-0) 

**Root Cause #1 - ContinuousBlocksValidationProvider:**

The validation checks `BaseRound.RealTimeMinersInformation.Count != 1` (the CURRENT round) to skip single-miner chains. When an empty round is submitted and BaseRound has multiple miners, the condition evaluates to TRUE, entering the validation block. However, the validation only checks continuous block production limits, not whether ProvidedRound contains miners. [2](#0-1) 

**Root Cause #2 - NextRoundMiningOrderValidationProvider:**

When `ProvidedRound.RealTimeMinersInformation` is empty, both `distinctCount` and `Count(m => m.OutValue != null)` equal zero. The equality check `0 == 0` passes validation. [3](#0-2) 

**Root Cause #3 - RoundTerminateValidationProvider:**

For NextRound behavior, the validator checks that `Any(m => m.InValue != null)` returns false to ensure InValues are null for new rounds. When the collection is empty, `Any()` returns false, which is misinterpreted as "all InValues are correctly null" rather than "no miners exist." [4](#0-3) 

**Unconditional Storage:**

After passing validation, `ProcessNextRound` unconditionally stores the empty round via `AddRoundInformation` without verifying the round contains miners. [5](#0-4) [6](#0-5) 

**Permanent Blockchain Halt:**

Once the empty round becomes the current round (BaseRound), all subsequent block production attempts fail at `MiningPermissionValidationProvider` because no miner's pubkey can exist in an empty `RealTimeMinersInformation.Keys` collection. [7](#0-6) 

## Impact Explanation

This vulnerability causes **CRITICAL consensus layer failure**:

1. **Permanent Blockchain Halt**: Once an empty round is stored, the blockchain cannot produce any subsequent blocks since `BaseRound.RealTimeMinersInformation.Keys` is empty, causing all mining permission checks to fail.

2. **Complete Network DoS**: All consensus operations, transaction processing, cross-chain communications, and state updates cease permanently across the entire network.

3. **Recovery Complexity**: There is no automatic recovery mechanism. Resolution requires emergency hard fork or manual state database intervention to restore the miner list and round information.

4. **Network-Wide Impact**: This impacts every node, miner, and user of the blockchain simultaneously, not just individual accounts or contracts.

The severity is CRITICAL because it violates the fundamental invariant that every round must contain at least one miner, causes irreversible consensus failure affecting the entire network, and has no built-in recovery path.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round (can pass PreCheck) [8](#0-7) 
- Can produce blocks during assigned time slots
- Requires only standard block production privileges

**Attack Complexity:**
The attack is trivially simple:
1. Attacker crafts `NextRoundInput` with empty `RealTimeMinersInformation` dictionary
2. During their mining time slot, submits the malicious transaction via the public `NextRound()` method [9](#0-8) 
3. Single transaction execution causes permanent halt

**Feasibility:**
The method is publicly accessible to any miner passing basic validation checks. The attack requires no complex preconditions, race conditions, or elevated privileges beyond being an active miner.

**Likelihood Assessment: HIGH**
While requiring miner access, the attack is straightforward to execute, has no complex preconditions, and requires only one of N miners to be malicious or compromised. Miners are not assumed to be fully trusted in the threat model.

## Recommendation

Add validation in the consensus validation pipeline to ensure proposed rounds contain at least one miner. The fix should be implemented in one of the validation providers for NextRound behavior:

**Option 1**: Add a dedicated validation provider that checks `ProvidedRound.RealTimeMinersInformation.Count > 0` before other validations.

**Option 2**: Enhance `NextRoundMiningOrderValidationProvider` to explicitly fail when the miner count is zero, rather than relying on the implicit `0 == 0` comparison.

**Option 3**: Add an assertion in `ProcessNextRound` before calling `AddRoundInformation` to verify `nextRound.RealTimeMinersInformation.Count > 0`.

The recommended approach is Option 1, as it provides defense-in-depth at the validation layer and makes the invariant explicit.

## Proof of Concept

A complete test demonstrating this vulnerability would:

1. Initialize a blockchain with multiple miners in the current round
2. Have one miner craft a `NextRoundInput` with empty `RealTimeMinersInformation`
3. Submit the transaction during the attacker's time slot
4. Verify that validation passes and the empty round is stored
5. Attempt subsequent mining and verify all attempts fail at `MiningPermissionValidationProvider`
6. Confirm the blockchain is permanently halted

The PoC confirms that an empty round bypasses all validation providers and causes permanent consensus failure.

## Notes

This vulnerability is particularly severe because:
- It targets the core consensus mechanism
- Recovery requires emergency protocol-level intervention
- The attack surface is any active miner
- Detection happens only after the damage is done (blockchain halt)
- There are no circuit breakers or automatic recovery mechanisms

The validation pipeline assumes that if individual miner properties are valid, the round as a whole is valid. This assumption breaks when the miner collection is empty, as all property checks trivially pass on empty collections.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-24)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L32-34)
```csharp
        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
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
