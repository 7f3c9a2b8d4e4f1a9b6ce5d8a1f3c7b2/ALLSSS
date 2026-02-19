### Title
Unvalidated TuneOrderInformation Allows Malicious Order Manipulation Causing Consensus DoS

### Summary
The `UpdateValue` method accepts `TuneOrderInformation` without validating that the order values are within the valid range [1, minersCount]. A malicious miner can set another miner's `FinalOrderOfNextRound` to 0 or other invalid values, which will be used during next round generation despite that miner having a non-zero `SupposedOrderOfNextRound`. This creates miners with `Order = 0` in the next round, breaking consensus logic that assumes all orders are in [1, minersCount], causing exceptions and consensus failure.

### Finding Description

The vulnerability exists in the interaction between miner categorization and order assignment across multiple functions: [1](#0-0) 

The categorization functions only check `SupposedOrderOfNextRound`, not `FinalOrderOfNextRound`. Miners with `SupposedOrderOfNextRound != 0` are categorized as "mined" regardless of their `FinalOrderOfNextRound` value. [2](#0-1) 

When processing `UpdateValueInput`, the contract directly applies `TuneOrderInformation` to set miners' `FinalOrderOfNextRound` without any validation of the values. [3](#0-2) 

The `UpdateValueValidationProvider` validates `OutValue`, `Signature`, and `PreviousInValue`, but completely ignores `TuneOrderInformation` contents. There are no checks that the order values are within [1, minersCount] or that they correspond to miners who actually have order conflicts. [4](#0-3) 

During next round generation, miners categorized as "mined" (those with `SupposedOrderOfNextRound != 0`) have their `FinalOrderOfNextRound` directly assigned as their `Order` in the next round. If `FinalOrderOfNextRound = 0`, this creates a miner with `Order = 0`, which is invalid. [5](#0-4) 

The `BreakContinuousMining` function assumes miners have valid orders and uses `.First(i => i.Order == 1)` which will throw an `InvalidOperationException` if no miner has `Order == 1` (because one was assigned `Order = 0`). [6](#0-5) 

The `GetMiningInterval` function expects to find miners with `Order == 1` and `Order == 2`, and accesses array indices that may not exist if orders are invalid.

### Impact Explanation

**Consensus Disruption - Critical DoS**: When a malicious miner sets another miner's `FinalOrderOfNextRound` to 0 (or any value outside [1, minersCount]), the next round generation will create a miner with an invalid order. This causes:

1. **Immediate consensus failure**: The `BreakContinuousMining` function will throw an exception when trying to find `Order == 1`, preventing the `NextRound` transaction from succeeding.

2. **Blockchain halt**: No new rounds can be generated, stopping all block production and halting the entire blockchain.

3. **Complete operational disruption**: All consensus-dependent operations (transactions, cross-chain communication, governance) are blocked.

4. **Affects entire network**: All nodes and users are impacted as the chain cannot progress.

The severity is **Critical** because:
- It causes complete denial of service of the blockchain
- Recovery requires manual intervention or emergency protocol changes
- Any active miner can execute the attack unilaterally
- No funds can be stolen during the DoS, but all economic activity halts

### Likelihood Explanation

**High Likelihood**: [7](#0-6) 

**Reachable Entry Point**: `UpdateValue` is a public method callable by any miner. [8](#0-7) 

**Feasible Preconditions**: The `PreCheck` only verifies the caller is in the current or previous miner list. Any active miner can exploit this - no special privileges needed beyond being an active consensus participant.

**Execution Practicality**: 
1. Attacker must be an active miner (realistic)
2. Another miner must have mined in the current round (always true in normal operation)
3. Attacker submits `UpdateValue` with crafted `TuneOrderInformation` setting victim's `FinalOrderOfNextRound = 0`
4. Next `NextRound` transaction attempts to use the corrupted data and fails

**Attack Complexity**: Low - single malicious transaction with manipulated input data.

**Economic Rationality**: While halting the chain harms the attacker's own mining rewards, motivations could include:
- Competitor attacking a rival blockchain
- Disgruntled miner protesting governance decisions
- Attacker holding short positions on the chain's token
- State-level actors attempting to disrupt the network

**Detection/Operational Constraints**: The malicious `UpdateValue` transaction will succeed and appear normal. The attack only manifests when the next round generation occurs, making attribution difficult.

### Recommendation

**Immediate Fix - Add TuneOrderInformation Validation**:

Add validation in `ProcessUpdateValue` before line 259-260 in `AEDPoSContract_ProcessConsensusInformation.cs`:

```csharp
// Validate TuneOrderInformation values
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Check miner exists
    Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key), 
        $"Invalid tune order: miner {tuneOrder.Key} not in current round");
    
    // Check order is in valid range [1, minersCount]
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
        $"Invalid tune order value: {tuneOrder.Value} must be in [1, {minersCount}]");
    
    // Check this miner actually mined (has non-zero SupposedOrderOfNextRound)
    var minerInRound = currentRound.RealTimeMinersInformation[tuneOrder.Key];
    Assert(minerInRound.SupposedOrderOfNextRound > 0,
        $"Cannot tune order for miner {tuneOrder.Key} who hasn't mined");
    
    // Check no duplicate orders
    var existingMinersWithSameOrder = currentRound.RealTimeMinersInformation.Values
        .Where(m => m.Pubkey != tuneOrder.Key && m.FinalOrderOfNextRound == tuneOrder.Value);
    Assert(!existingMinersWithSameOrder.Any(),
        $"Order {tuneOrder.Value} already assigned to another miner");
}
```

**Alternative Fix - Add Validation in UpdateValueValidationProvider**:

Extend the `UpdateValueValidationProvider.ValidateHeaderInformation` method to validate `TuneOrderInformation`.

**Additional Hardening**:

Add defensive checks in `GenerateNextRoundInformation` to assert that all assigned orders are in valid range [1, minersCount] before creating the next round.

**Test Cases**:

1. Test that `UpdateValue` with `TuneOrderInformation` containing order value 0 is rejected
2. Test that `TuneOrderInformation` with order values > minersCount is rejected  
3. Test that `TuneOrderInformation` for miners who haven't mined is rejected
4. Test that duplicate order assignments are rejected
5. Test that legitimate order conflict resolutions still work correctly

### Proof of Concept

**Initial State**:
- Current round R with 5 miners: A, B, C, D, E
- Miner A has legitimately mined: `SupposedOrderOfNextRound = 3`, `FinalOrderOfNextRound = 3`
- Miner B is the attacker (active miner)

**Attack Steps**:

1. **Attacker crafts malicious UpdateValueInput**:
   - Miner B produces their legitimate block data
   - In `TuneOrderInformation`, B includes: `{"A": 0}` (setting A's FinalOrderOfNextRound to 0)
   
2. **Attacker submits UpdateValue transaction**:
   - Transaction passes `PreCheck` (B is an active miner)
   - Transaction passes validation (UpdateValueValidationProvider doesn't check TuneOrderInformation)
   - Line 260 in ProcessUpdateValue executes: `currentRound.RealTimeMinersInformation["A"].FinalOrderOfNextRound = 0`
   - Transaction succeeds

3. **Current Round State After Attack**:
   - Miner A: `SupposedOrderOfNextRound = 3`, `FinalOrderOfNextRound = 0` (INCONSISTENT)

4. **Next Round Generation Attempt**:
   - Extra block producer calls `NextRound`
   - `GenerateNextRoundInformation` is executed
   - Line 125-128: `GetMinedMiners()` returns miners with `SupposedOrderOfNextRound != 0` → includes Miner A
   - Line 26: Orders `minersMinedCurrentRound` by `FinalOrderOfNextRound` → Miner A is first (order 0)
   - Line 28-32: Creates `MinerInRound` for A with `Order = 0`
   - Line 67: Calls `BreakContinuousMining`
   - Line 79: Executes `.First(i => i.Order == 1)` → **THROWS InvalidOperationException** (no miner has Order == 1)

**Expected Result**: Next round generated successfully with valid orders [1, 5]

**Actual Result**: `NextRound` transaction fails with exception, consensus is stuck, blockchain halted

**Success Condition**: Blockchain cannot produce new blocks after the attack; manual intervention required to recover

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L73-90)
```csharp
    private void BreakContinuousMining(ref Round nextRound)
    {
        var minersCount = RealTimeMinersInformation.Count;
        if (minersCount <= 1) return;

        // First miner of next round != Extra block producer of current round
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-135)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }

    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
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

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
