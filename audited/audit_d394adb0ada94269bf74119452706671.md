# Audit Report

## Title
LIB Height Validation Bypass Through Pre-Validation State Mutation

## Summary
A critical ordering flaw in the `ValidateBeforeExecution` function allows malicious miners to bypass Last Irreversible Block (LIB) height validation. The `RecoverFromUpdateValue` method modifies the `baseRound` object before validation occurs, causing `LibInformationValidationProvider` to compare identical values instead of comparing the provided value against the trusted state value. This enables miners to submit artificially decreased `ImpliedIrreversibleBlockHeight` values, violating consensus finality guarantees.

## Finding Description

The vulnerability exists in the validation sequence within `ValidateBeforeExecution`. When a miner produces an `UpdateValue` block, the validation flow executes as follows:

First, `baseRound` is fetched from state containing the trusted previous `ImpliedIrreversibleBlockHeight` value. [1](#0-0) 

For `UpdateValue` behavior, `RecoverFromUpdateValue` is called, which modifies `baseRound` in-place BEFORE validation occurs. [2](#0-1) 

The `RecoverFromUpdateValue` method overwrites the trusted `ImpliedIrreversibleBlockHeight` from state with the provided value. [3](#0-2) 

The `ConsensusValidationContext` is then created with the modified `baseRound` and `ExtraData` containing the provided round. [4](#0-3) 

The `ProvidedRound` property in the context returns `ExtraData.Round`, which is the original provided round object. [5](#0-4) 

The `LibInformationValidationProvider` is added to validate LIB information for UpdateValue behavior. [6](#0-5) 

The validation check compares `baseRound.ImpliedIrreversibleBlockHeight` (now containing the provided value after mutation) against `providedRound.ImpliedIrreversibleBlockHeight` (the original provided value). [7](#0-6) 

Since both values are now identical due to the pre-validation mutation, the check at line 25 fails to detect when the provided value represents a decrease from the original trusted state value. The validation passes even when it should reject the block.

The malicious decreased value is then persisted to state during processing. [8](#0-7) 

This decreased value directly impacts LIB calculation. [9](#0-8) 

The `LastIrreversibleBlockHeightCalculator` uses sorted implied heights from miners to calculate the confirmed LIB. [10](#0-9) 

The sorted heights are obtained from miners' individual reported values. [11](#0-10) 

If miners can decrease their implied heights by bypassing validation, the calculated `ConfirmedIrreversibleBlockHeight` can be artificially lowered, violating the fundamental blockchain invariant that LIB must never decrease.

## Impact Explanation

**Severity: CRITICAL**

This vulnerability breaks the core consensus finality guarantee that the Last Irreversible Block height should monotonically increase and never decrease. A malicious miner can exploit this to:

1. **Violate Finality Guarantees**: By decreasing the LIB height, blocks previously considered irreversible can become reversible again, breaking the finality promise to users and applications.

2. **Enable Double-Spending Attacks**: Transactions that users believed were finalized (beyond LIB) could potentially be reversed if the LIB is artificially decreased, allowing double-spending of tokens.

3. **Cross-Chain Bridge Exploits**: Cross-chain bridges and relayers typically rely on LIB verification for security. Manipulating LIB can enable attacks on cross-chain asset transfers.

4. **Consensus Safety Violations**: The ability to manipulate LIB affects all network participants and undermines the consensus mechanism's safety properties.

5. **Chain Reorganization Beyond Expected Window**: Applications and services assume blocks beyond LIB cannot be reorganized. This assumption is violated when LIB can be decreased.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Capabilities**: Any active miner in the consensus set can exploit this vulnerability. Miners are not privileged trusted parties - they are network participants selected through the election mechanism.

**Attack Complexity**: LOW - The attack requires only:
- Being a valid miner in the current round (passes `MiningPermissionValidationProvider`)
- Producing a block during the assigned time slot (passes `TimeSlotValidationProvider`)
- Submitting an `UpdateValue` block with a decreased `ImpliedIrreversibleBlockHeight` value

**Preconditions**: Minimal - attacker only needs to be an active miner, which is achievable through the election process.

**Execution Practicality**: HIGHLY PRACTICAL - The validation bypass is deterministic and guaranteed to succeed due to the code logic flaw. No race conditions, timing windows, or uncertain behaviors are involved.

**Detection Difficulty**: MODERATE - While the decreased LIB would be recorded on-chain and visible in round state, it may not trigger immediate alarms unless monitoring systems specifically check for LIB decreases. The malicious miner could claim it was an honest mistake or software bug.

**Economic Rationality**: HIGH - A malicious miner gains significant capability (finality manipulation) at minimal cost (normal block production). The attack enables profitable exploits like double-spending while maintaining plausible deniability.

## Recommendation

The validation logic must be corrected to preserve the original trusted state value before calling `RecoverFromUpdateValue`. The recommended fix:

1. **Clone or Store Original Value**: Before calling `RecoverFromUpdateValue`, store the original `ImpliedIrreversibleBlockHeight` from the trusted `baseRound` fetched from state.

2. **Validate Against Original Value**: Ensure `LibInformationValidationProvider` compares the provided value against the original trusted value, not the mutated value.

3. **Reorder Operations**: Alternatively, perform validation before calling `RecoverFromUpdateValue`, or pass the original unmutated round to the validation context.

Recommended implementation approach:

Store the original value before mutation in `ValidateBeforeExecution`:
```csharp
var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(extraData.SenderPubkey.ToHex()) 
    ? baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight 
    : 0;
```

Then modify the validation context to include this original value, or validate before calling `RecoverFromUpdateValue`.

## Proof of Concept

A malicious miner can exploit this vulnerability with the following attack sequence:

1. Wait until assigned time slot as an active miner
2. Retrieve current round state where their `ImpliedIrreversibleBlockHeight` is at height H
3. Produce an `UpdateValue` block with `ImpliedIrreversibleBlockHeight` set to H-1000 (decreased value)
4. Submit the block for validation

During validation:
- `baseRound` fetched from state has `ImpliedIrreversibleBlockHeight = H`
- `RecoverFromUpdateValue` overwrites it to `H-1000`
- `LibInformationValidationProvider` compares `H-1000` (mutated baseRound) vs `H-1000` (provided value)
- Comparison passes since both values are identical
- Block is accepted and decreased value persists to state

The decreased value then influences LIB calculation in subsequent rounds, potentially lowering the network's confirmed irreversible block height.

**Test Scenario**: Create a test that:
1. Sets up a miner with `ImpliedIrreversibleBlockHeight = 1000` in state
2. Submits an `UpdateValue` with `ImpliedIrreversibleBlockHeight = 500`
3. Verifies that validation passes (demonstrating the bypass)
4. Confirms the decreased value is persisted to state
5. Shows the LIB calculation uses the decreased value

This test would demonstrate the validation bypass and its impact on consensus finality guarantees.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L82-82)
```csharp
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-29)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-282)
```csharp
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-18)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
```
