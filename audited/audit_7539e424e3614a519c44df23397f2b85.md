### Title
Stale Continuous Block Counter Bypasses Severe Status Emergency Limit

### Summary
During Severe emergency status, `GetMaximumBlocksCount()` returns 1 to drastically limit block production, but the validation system uses a stale `LatestPubkeyToTinyBlocksCount` counter that is only decremented (not reset) when the same miner continues producing blocks. This allows a miner to produce multiple blocks (up to their pre-emergency counter value) instead of being limited to 1 block, completely undermining the emergency safety mechanism designed to prevent the chain from advancing too far ahead of the Last Irreversible Block (LIB).

### Finding Description

**Root Cause:**

When the system enters Severe status (when `R >= R_LIB + CB1`), `GetMaximumBlocksCount()` returns 1 to enforce emergency limits: [1](#0-0) 

However, the validation performed BEFORE block execution uses the stale `State.LatestPubkeyToTinyBlocksCount` value from state: [2](#0-1) 

The `ContinuousBlocksValidationProvider` only rejects blocks when `BlocksCount < 0`: [3](#0-2) 

**Why Protection Fails:**

The critical flaw is in `ResetLatestProviderToTinyBlocksCount()`, which is called AFTER validation and execution. When the same miner continues producing blocks, it only decrements the existing counter: [4](#0-3) 

The new emergency limit (`minersCountInTheory = 1`) is only used when a DIFFERENT miner takes over: [5](#0-4) 

**Execution Path:**

1. `ValidateConsensusBeforeExecution` → `ValidateBeforeExecution` creates validation context with stale counter
2. `ContinuousBlocksValidationProvider.ValidateHeaderInformation` checks only if `BlocksCount < 0`
3. Block executes → `ProcessConsensusInformation` is called: [6](#0-5) 

4. `GetMaximumBlocksCount()` returns 1, but `ResetLatestProviderToTinyBlocksCount(1)` only decrements the old value

### Impact Explanation

**Concrete Harm:**

The Severe status is triggered when the current round number is at least CB1 rounds (max(8, MaximumTinyBlocksCount) = 8) ahead of the LIB round. This is a critical safety mechanism to prevent chain instability. When bypassed, the chain can continue advancing dangerously far ahead of the LIB. [7](#0-6) 

**Quantified Impact:**

If a miner had `BlocksCount = N` before Severe status (where N can be up to `MaximumTinyBlocksCount - 1 = 7`), they can produce N+1 blocks during emergency instead of the intended 1 block. With the default value: [8](#0-7) 

This means up to 8 blocks can be produced when only 1 should be allowed - an 8x violation of the emergency limit.

**Who Is Affected:**

- **Chain Security:** The LIB safety mechanism is compromised, increasing fork risk and chain reorganization vulnerability
- **All Network Participants:** Chain instability affects finality guarantees and transaction irreversibility
- **Emergency Response:** The emergency brake mechanism becomes ineffective

### Likelihood Explanation

**Attacker Capabilities:**

Any legitimate miner who has been producing consecutive blocks can naturally have a non-zero `BlocksCount` value. No special permissions or manipulation is required beyond normal mining operations.

**Attack Complexity:**

The vulnerability triggers automatically during normal consensus operation when:
1. A miner has been producing consecutive blocks (common during normal operation)
2. System transitions to Severe status due to LIB lag
3. Same miner continues mining (natural behavior)

**Feasibility:**

- **Preconditions:** Highly realistic - miners regularly produce consecutive blocks, and Severe status can occur during network issues or consensus delays
- **Detection:** The issue is architectural and cannot be detected from external observation
- **Operational Constraints:** None - this is normal consensus flow

**Probability:**

HIGH - This occurs naturally whenever:
- Network conditions cause LIB to lag (network partitions, consensus delays)
- A miner happens to be producing blocks when Severe status triggers

### Recommendation

**Code-Level Mitigation:**

Modify `ResetLatestProviderToTinyBlocksCount` to immediately reset to the current limit when it has changed, regardless of whether it's the same miner:

```csharp
private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
{
    LatestPubkeyToTinyBlocksCount currentValue;
    if (State.LatestPubkeyToTinyBlocksCount.Value == null)
    {
        currentValue = new LatestPubkeyToTinyBlocksCount
        {
            Pubkey = _processingBlockMinerPubkey,
            BlocksCount = minersCountInTheory.Sub(1)
        };
        State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
    }
    else
    {
        currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
        if (currentValue.Pubkey == _processingBlockMinerPubkey)
        {
            // NEW: Check if limit has decreased (e.g., entering Severe status)
            var newCount = currentValue.BlocksCount.Sub(1);
            var emergencyLimit = minersCountInTheory.Sub(1);
            State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = Math.Min(newCount, emergencyLimit)
            };
        }
        else
        {
            State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = minersCountInTheory.Sub(1)
            };
        }
    }
}
```

**Alternative: Validation-Time Check:**

Add explicit Severe status detection in `ContinuousBlocksValidationProvider` to enforce the limit during validation:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    
    if (validationContext.ProvidedRound.RoundNumber > 2 &&
        validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
    {
        // NEW: Check if in Severe status and enforce immediate limit
        var libRoundNumber = validationContext.BaseRound.ConfirmedIrreversibleBlockRoundNumber;
        var currentRoundNumber = validationContext.BaseRound.RoundNumber;
        var severeThreshold = Math.Max(8, MaximumTinyBlocksCount);
        
        if (currentRoundNumber >= libRoundNumber + severeThreshold)
        {
            // In Severe status - strictly enforce limit of 1 block
            if (latestPubkeyToTinyBlocksCount?.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Severe status: limit exceeded";
                return validationResult;
            }
        }
        
        // Existing check
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

**Test Cases:**

1. Test Severe status entry with miner having BlocksCount = 5 - verify only 1 more block allowed
2. Test Severe status exit - verify counter properly resets to normal limits
3. Test miner switch during Severe status - verify new miner gets correct limit
4. Test BlocksCount boundary conditions (0, -1) during status transitions

### Proof of Concept

**Required Initial State:**

- System in Normal status
- Miner A actively producing blocks
- `State.LatestPubkeyToTinyBlocksCount = {Pubkey: A, BlocksCount: 5}`
- Current round R = 40, LIB round R_LIB = 32
- Next round advances to R = 40 where R >= R_LIB + 8 (Severe threshold)

**Transaction Steps:**

1. **Block N+1 (Severe Status Triggered):**
   - Validation: `BlocksCount = 5` (not < 0) → **PASSES**
   - Execution: `GetMaximumBlocksCount()` returns 1, `ResetLatestProviderToTinyBlocksCount(1)` sets `BlocksCount = 5 - 1 = 4`

2. **Block N+2:**
   - Validation: `BlocksCount = 4` → **PASSES**
   - Execution: `BlocksCount = 4 - 1 = 3`

3. **Block N+3:**
   - Validation: `BlocksCount = 3` → **PASSES**
   - Execution: `BlocksCount = 3 - 1 = 2`

4. **Block N+4:**
   - Validation: `BlocksCount = 2` → **PASSES**
   - Execution: `BlocksCount = 2 - 1 = 1`

5. **Block N+5:**
   - Validation: `BlocksCount = 1` → **PASSES**
   - Execution: `BlocksCount = 1 - 1 = 0`

6. **Block N+6:**
   - Validation: `BlocksCount = 0` → **PASSES**
   - Execution: `BlocksCount = 0 - 1 = -1`

7. **Block N+7:**
   - Validation: `BlocksCount = -1` (< 0) → **FAILS**

**Expected vs Actual Result:**

- **Expected:** Only 1 block allowed during Severe status
- **Actual:** 6 blocks produced (N+1 through N+6) before rejection

**Success Condition:**

Miner A successfully produces 6 consecutive blocks during Severe emergency status when the system intended to limit production to 1 block, demonstrating complete bypass of the emergency safety mechanism.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L114-117)
```csharp
        /// <summary>
        ///     Stands for CB1
        /// </summary>
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-59)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L16-23)
```csharp
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L352-357)
```csharp
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L358-363)
```csharp
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
