### Title
Missing ActualMiningTime Validation Allows Time Slot Bypass and Reward Inflation

### Summary
The AEDPoS consensus contract does not validate that the `ActualMiningTime` provided in `UpdateValueInput` and `TinyBlockInput` matches the actual block time (`Context.CurrentBlockTime`). A malicious miner can provide fabricated `ActualMiningTime` values within their expired time slot to bypass `TimeSlotValidationProvider` checks, produce unlimited blocks beyond their assigned time, and inflate their `ProducedBlocks` counter, leading to excessive reward minting at term end.

### Finding Description

**Root Cause:**
The contract accepts user-provided `ActualMiningTime` values without verification. [1](#0-0) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, but does NOT validate that `ActualMiningTime` corresponds to the actual block time.

**Attack Path:**

1. During validation, `RecoverFromUpdateValue` adds the attacker-provided `ActualMiningTime` to the `baseRound` used for validation: [2](#0-1) 

2. `TimeSlotValidationProvider.CheckMinerTimeSlot` checks if `latestActualMiningTime < endOfExpectedTimeSlot`, but uses the recovered (attacker-controlled) time: [3](#0-2) 

3. During execution, the provided `ActualMiningTime` is stored directly to state without validation against `Context.CurrentBlockTime`: [4](#0-3) 

4. Each block increments `ProducedBlocks` by exactly 1: [5](#0-4) 

5. `ProducedBlocks` accumulates across rounds within a term: [6](#0-5) 

6. At term end, `DonateMiningReward` calculates rewards as `minedBlocks * rewardPerBlock` where `minedBlocks = previousRound.GetMinedBlocks()`: [7](#0-6) 

7. `GetMinedBlocks()` sums all miners' inflated `ProducedBlocks` values: [8](#0-7) 

**Why Existing Protections Fail:**

The legitimate code in `GetConsensusExtraDataToPublishOutValue` sets `ActualMiningTime = Context.CurrentBlockTime`: [9](#0-8) 

However, a malicious miner can bypass this by directly crafting transactions with fake timestamps. The contract has no enforcement that the provided value matches the actual time.

### Impact Explanation

**Direct Financial Impact:**
- A malicious miner can produce unlimited blocks by repeatedly providing `ActualMiningTime` values that fall within their expired time slot (e.g., providing T+3999ms when current time is T+10000ms, as long as their slot was [T, T+4000ms])
- Each fraudulent block increments their `ProducedBlocks` counter
- At term end, total mining rewards are calculated as: `amount = GetMinedBlocks() * GetMiningRewardPerBlock()`
- The inflated `ProducedBlocks` directly increases the total donation to Treasury and subsequent reward distribution
- If initial reward is 125,000 tokens per block and a miner inflates their count by 1,000 blocks, they steal 125,000,000 additional tokens from the reward pool

**Consensus Integrity Impact:**
- Breaks the fundamental time slot fairness mechanism
- Allows a single miner to dominate block production beyond their allocated slots
- Undermines the entire AEDPoS round-robin mining schedule

**Affected Parties:**
- Honest miners receive reduced rewards due to inflated denominator
- Token holders experience unexpected inflation
- Treasury/Profit contracts distribute based on corrupted data

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an elected miner in the current or previous round (validated by `PreCheck()`)
- Must modify their mining client to generate transactions with fabricated `ActualMiningTime` values
- Does not require compromising other miners or governance

**Attack Complexity:**
- LOW: Simple modification of transaction input field
- The contract-level validation has no defense against this
- Network-level timestamp validation (BlockValidationProvider checking block.Header.Time) only prevents blocks too far in the future, not mismatches between block time and consensus ActualMiningTime

**Feasibility Conditions:**
- Attack is executable in any term where the attacker is a valid miner
- No special network conditions required
- Once initial fake time is stored, subsequent fakes build on it

**Detection Constraints:**
- Contract provides no event or check to detect ActualMiningTime manipulation
- Off-chain analysis could detect the discrepancy between block timestamps and stored ActualMiningTimes
- But by then, rewards have already been minted

**Probability:**
- HIGH if a malicious miner exists in the miner set
- The attack is deterministic once launched
- Economic incentive is significant (reward inflation)

### Recommendation

**Immediate Fix:**
Add validation in `ProcessUpdateValue` and `ProcessTinyBlock` to ensure the provided `ActualMiningTime` matches the current block time:

```csharp
// In ProcessUpdateValue, before line 243:
Assert(updateValueInput.ActualMiningTime == Context.CurrentBlockTime,
    "ActualMiningTime must match current block time");

// In ProcessTinyBlock, before line 304:
Assert(tinyBlockInput.ActualMiningTime == Context.CurrentBlockTime,
    "ActualMiningTime must match current block time");
```

**Additional Hardening:**
Add a validation provider to check ActualMiningTime consistency:

```csharp
public class ActualMiningTimeValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Validate that provided ActualMiningTime is close to current time
        // (allowing small clock drift)
        var validationResult = new ValidationResult();
        var providedTime = validationContext.ProvidedRound
            .RealTimeMinersInformation[validationContext.SenderPubkey]
            .ActualMiningTimes.Last();
        
        // Allow 5 second tolerance for clock drift
        if (Math.Abs((providedTime - validationContext.CurrentBlockTime).Seconds) > 5)
        {
            validationResult.Message = "ActualMiningTime deviates too much from block time";
            return validationResult;
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

Register this validator in `ValidateBeforeExecution` alongside other providers.

**Test Cases:**
1. Test that UpdateValue with ActualMiningTime != Context.CurrentBlockTime is rejected
2. Test that a miner cannot produce blocks with backdated ActualMiningTime values
3. Test that GetMinedBlocks() returns accurate counts after validation fix
4. Test reward calculation with attempted manipulation is prevented

### Proof of Concept

**Initial State:**
- Miner A is in the current round with time slot [T, T+4000ms]
- Current block height: N
- Miner A's ProducedBlocks: 10

**Attack Sequence:**

**Block N+1 (time T+1000ms):**
- Miner A legitimately produces block with ActualMiningTime = T+1000ms
- ProducedBlocks = 11

**Block N+2 (time T+6000ms - AFTER time slot expired):**
- Miner A crafts UpdateValueInput with ActualMiningTime = T+3999ms (within expired slot)
- Validation: RecoverFromUpdateValue adds T+3999ms to baseRound
- TimeSlotValidationProvider checks: T+3999ms < T+4000ms → PASS ✓
- Execution: Stores ActualMiningTime = T+3999ms, ProducedBlocks = 12 ✗

**Block N+3 (time T+8000ms):**
- Miner A crafts UpdateValueInput with ActualMiningTime = T+3998ms
- Validation uses recovered time T+3998ms < T+4000ms → PASS ✓
- ProducedBlocks = 13 ✗

**Miner A repeats this arbitrarily many times within the term**

**At Term End:**
- Miner A's ProducedBlocks = 10 (legitimate) + X (fraudulent)
- Total reward = (10 + X) * rewardPerBlock instead of 10 * rewardPerBlock
- Excess tokens minted to Treasury: X * rewardPerBlock

**Success Condition:**
Miner A receives rewards for blocks they never legitimately produced during their time slot, provable by comparing block timestamps against stored ActualMiningTimes.

**Notes:**

This vulnerability exists because the contract trusts user-provided timing data without verification. While network-level protections may prevent some exploitation scenarios, the smart contract itself has no defense mechanism. The attack is particularly severe because:

1. It directly inflates the token supply through excessive Treasury donations
2. The `ProducedBlocks` counter is the sole basis for reward calculation
3. No audit trail exists to prove the manipulation occurred (beyond off-chain timestamp analysis)
4. The vulnerability compounds across all blocks in a term

The fix must be implemented at the contract level to satisfy the defense-in-depth principle, regardless of network-level timestamp validation.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L124-127)
```csharp
    public long GetMinedBlocks()
    {
        return RealTimeMinersInformation.Values.Sum(minerInRound => minerInRound.ProducedBlocks);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```
