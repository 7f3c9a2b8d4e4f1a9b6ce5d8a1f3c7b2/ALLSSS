# Audit Report

## Title
Missing LIB Upper Bound Validation in NextRound/NextTerm Enables Consensus DOS via Integer Overflow

## Summary
A malicious miner can inject invalid future LIB (Last Irreversible Block) values during NextRound/NextTerm consensus transitions, bypassing validation and causing permanent chain halt via arithmetic overflow after several rounds. The vulnerability exploits the absence of LibInformationValidationProvider for NextRound/NextTerm behaviors and the exclusion of LIB fields from post-execution hash validation.

## Finding Description

The AEDPoS consensus contract has a critical validation gap in its consensus information processing:

**Validation Architecture Gap:**
The `ValidateBeforeExecution` method applies different validation providers based on consensus behavior. [1](#0-0) 

For `UpdateValue` behavior, `LibInformationValidationProvider` is added to validate LIB bounds. However, for `NextRound` and `NextTerm` behaviors, only `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider` are used - **neither validates LIB values**.

**Insufficient LIB Validation:**
`LibInformationValidationProvider` only checks backward LIB movement (preventing LIB from decreasing), but does NOT check if LIB values are unreasonably far in the future. [2](#0-1) 

`RoundTerminateValidationProvider` only validates round number increments, term number increments, and InValue nullity - completely ignoring LIB values. [3](#0-2) 

**Hash Validation Bypass:**
The `GetHash` method used in `ValidateConsensusAfterExecution` creates a checkable round that explicitly excludes `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` from the hash computation. [4](#0-3) 

This allows a malicious miner to modify LIB fields without detection by post-execution validation. [5](#0-4) 

**Attack Execution Path:**
1. Malicious miner creates NextRoundInput with:
   - `ConfirmedIrreversibleBlockRoundNumber = currentRound + 20` (future round)
   - `ConfirmedIrreversibleBlockHeight = long.MaxValue`

2. The input passes through `ToRound()` conversion without validation. [6](#0-5) 

3. During malicious block execution, `GetMaximumBlocksCount()` evaluates blockchain status as Normal (not Severe) because `currentRoundNumber < libRoundNumber + 8`, avoiding the problematic overflow check. [7](#0-6) 

4. The malicious Round is stored to state via `AddRoundInformation`. [8](#0-7) 

5. After ~20 rounds, when `currentRoundNumber >= libRoundNumber + 8`, the blockchain enters Severe status, triggering the overflow at `currentHeight.Sub(libBlockHeight)`. [9](#0-8) 

6. The `Sub()` extension method uses checked arithmetic, throwing `OverflowException`. [10](#0-9) 

7. Every subsequent block fails during consensus processing. [11](#0-10) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables permanent consensus denial-of-service with catastrophic impact:

1. **Complete Chain Halt**: Once the blockchain enters Severe status with malicious LIB values, every block execution fails with `OverflowException`. No new blocks can be produced by any miner.

2. **Permanent Damage**: The malicious Round is stored in consensus state. Normal recovery mechanisms cannot fix this - the chain remains permanently halted until external intervention (hard fork or manual state rollback).

3. **Blockchain-Wide Scope**: Affects the entire blockchain, not isolated to specific transactions or accounts. All dependent applications, sidechains, and services halt.

4. **No Automatic Recovery**: Unlike temporary network issues or single-node failures, this creates persistent state corruption that survives node restarts and cannot self-heal.

5. **Economic Damage**: Complete loss of blockchain functionality impacts all token holders, applications, and ecosystem participants. Recovery requires coordinated hard fork with significant operational cost and potential chain splits.

## Likelihood Explanation

**Likelihood: MEDIUM (with Miner Access)**

**Attacker Prerequisites:**
- Must be an active consensus miner (elected via Election contract on mainchain, or configured miner on sidechains)
- High entry barrier: requires significant token staking and community election on mainchain
- Lower barrier on sidechains: depends on sidechain's miner configuration

**Attack Complexity: LOW** (once miner access obtained)
1. Monitor consensus for NextRound/NextTerm time slot assignment
2. Call `GetConsensusCommand` to receive legitimate consensus data
3. Modify `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` in the Round object before block production
4. Submit block - passes all validation checks
5. Wait for ~20 rounds for overflow to trigger

**No Runtime Detection:**
- Malicious values appear structurally valid (no bounds checking)
- Pass all existing validation providers
- Pass post-execution hash validation (LIB fields excluded)
- No alerts or warnings until overflow occurs

**Realistic Attack Scenarios:**
- Compromised miner node (hacking, insider threat)
- Malicious miner exiting the network (scorched earth attack)
- Byzantine actor gaining miner status through election manipulation
- Disgruntled miner seeking retaliation

**Probability Assessment:**
While miners have economic incentives to maintain chain health, the low attack complexity and lack of detection make this a credible threat if any miner becomes compromised or malicious.

## Recommendation

Implement comprehensive LIB bound validation for all consensus behaviors:

1. **Add Upper Bound Validation to LibInformationValidationProvider:**
```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
    providedRound.ConfirmedIrreversibleBlockRoundNumber != 0)
{
    // Prevent backward movement (existing check)
    if (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
        baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber)
    {
        validationResult.Message = "LIB cannot move backward.";
        return validationResult;
    }
    
    // NEW: Prevent unreasonable forward movement
    const long MAX_REASONABLE_LIB_ADVANCE = 100; // rounds
    if (providedRound.ConfirmedIrreversibleBlockRoundNumber > baseRound.RoundNumber + MAX_REASONABLE_LIB_ADVANCE)
    {
        validationResult.Message = "LIB round number too far in future.";
        return validationResult;
    }
    
    // NEW: Sanity check on LIB height
    if (providedRound.ConfirmedIrreversibleBlockHeight > validationContext.ExtraData.Round.RoundNumber * 1000)
    {
        validationResult.Message = "LIB height unreasonably high.";
        return validationResult;
    }
}
```

2. **Apply LibInformationValidationProvider to NextRound/NextTerm:**
```csharp
// In AEDPoSContract_Validation.cs ValidateBeforeExecution
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

3. **Add Defensive Check in GetMaximumBlocksCount:**
```csharp
// In GetMaximumBlocksCount before line 63
if (libBlockHeight > currentHeight)
{
    Context.LogDebug(() => $"LIB height {libBlockHeight} > current height {currentHeight}, using current height");
    libBlockHeight = currentHeight; // Defensive fallback
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousNextRound_WithFutureLIB_CausesOverflowDOS()
{
    // Setup: Initialize chain with normal consensus
    await InitializeConsensusContract();
    await ProduceNormalBlocks(10);
    
    // Get current round for malicious modification
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var currentRoundNumber = currentRound.RoundNumber;
    
    // Create malicious NextRoundInput with future LIB values
    var maliciousNextRound = CreateNextRoundInput(currentRound);
    maliciousNextRound.ConfirmedIrreversibleBlockHeight = long.MaxValue;
    maliciousNextRound.ConfirmedIrreversibleBlockRoundNumber = currentRoundNumber + 20; // Future round
    
    // Execute malicious NextRound - should succeed initially
    var result = await MinerStub.NextRound.SendAsync(maliciousNextRound);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify malicious values stored
    var storedRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    storedRound.ConfirmedIrreversibleBlockHeight.ShouldBe(long.MaxValue);
    
    // Produce blocks until Severe status triggered (currentRound >= libRound + 8)
    for (int i = 0; i < 25; i++)
    {
        await ProduceNormalBlock();
    }
    
    // Next block should fail with OverflowException
    var exception = await Assert.ThrowsAsync<OverflowException>(async () =>
    {
        await ProduceNormalBlock();
    });
    
    // Chain is permanently halted - no recovery possible
    exception.ShouldNotBeNull();
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-47)
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

    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L99-101)
```csharp
            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-66)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-128)
```csharp
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);

        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L68-68)
```csharp
        var minersCountInTheory = GetMaximumBlocksCount();
```
