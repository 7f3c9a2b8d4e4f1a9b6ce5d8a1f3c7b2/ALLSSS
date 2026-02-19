### Title
Missing Duplicate UpdateValue Check Allows Miners to Inflate Block Production Counter and Steal Mining Rewards

### Summary
The consensus validation logic fails to verify that a miner's `OutValue` is null before accepting an `UpdateValue` transaction. A malicious miner can produce multiple blocks with `UpdateValue` behavior in the same round, artificially inflating their `ProducedBlocks` counter and stealing a disproportionate share of mining rewards from honest miners.

### Finding Description

The vulnerability exists in the consensus validation flow where `UpdateValue` behavior is accepted without checking if the miner has already mined in the current round.

**Root Cause:**

The `UpdateValueValidationProvider` only validates that the `OutValue` is filled in the **provided** round data (from consensus extra data), but does not check whether `OutValue` is **already set** in the current state: [1](#0-0) 

During validation, `RecoverFromUpdateValue` blindly overwrites the existing `OutValue` without any check: [2](#0-1) 

The `ProcessUpdateValue` method then unconditionally increments the `ProducedBlocks` counter: [3](#0-2) 

**Why Protections Fail:**

While `GetConsensusBehaviour()` correctly checks if `OutValue == null` to determine whether to return `UpdateValue` behavior: [4](#0-3) 

This check only applies when the miner uses the standard consensus command flow. A malicious miner can bypass this by:
1. Modifying their node software to force `UpdateValue` behavior
2. Crafting consensus extra data with `UpdateValue` behavior even after `OutValue` is set
3. Broadcasting blocks that other nodes will accept because validation doesn't verify the miner hasn't already mined

The only transaction-level protection prevents multiple consensus transactions in the **same block**, not the same **round**: [5](#0-4) 

### Impact Explanation

**Direct Financial Theft:**

Mining rewards are distributed based on each miner's `ProducedBlocks` count. The reward share calculation directly uses this counter: [6](#0-5) [7](#0-6) 

**Quantified Impact:**

- A malicious miner with 1 of N mining slots can produce M extra `UpdateValue` blocks per round
- Their `ProducedBlocks` becomes (1 + M) instead of 1
- If all other miners are honest with 1 block each, the malicious miner receives `(1+M)/(N-1+1+M)` of total rewards instead of `1/N`
- For example, with N=7 miners and M=3 extra blocks: attacker gets 4/10 = 40% instead of 1/7 = 14.3%, stealing ~26% of the reward pool
- This directly reduces honest miners' rewards proportionally

**Who Is Affected:**

- All honest miners lose rewards proportional to the inflated counter
- The protocol's consensus integrity is compromised as block production counts become unreliable
- Long-term: erosion of trust in the consensus mechanism

### Likelihood Explanation

**Attacker Capabilities:**

A malicious miner needs to:
1. Control a block producer node (realistic for any miner)
2. Modify node software to bypass `GetConsensusCommand` behavior selection
3. Generate consensus extra data with `UpdateValue` behavior
4. Produce blocks within their time slot or immediately after

**Attack Complexity:**

- **Low to Medium**: Requires modifying consensus client code, but the attack logic is straightforward
- The consensus extra data generation is well-documented in the codebase
- No cryptographic attacks or complex state manipulation required

**Feasibility Conditions:**

- **Highly Feasible**: Byzantine miners are an expected threat model in blockchain consensus
- The attack leaves no invalid signatures or cryptographic evidence
- Validation by other nodes will **accept** the malicious blocks because the validation logic is flawed
- Can be executed repeatedly every round for sustained profit

**Detection Constraints:**

- **Difficult to Detect**: The blocks appear valid to all validators
- Only statistical analysis of abnormally high `ProducedBlocks` counts over time might reveal the attack
- No on-chain mechanism prevents or alerts on this behavior

**Probability: High** - The attack is practical, profitable, and difficult to detect. Any miner with sufficient technical capability and malicious intent can execute this exploit.

### Recommendation

**Code-Level Mitigation:**

Add an explicit check in `UpdateValueValidationProvider` to verify the miner hasn't already mined in the current round:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    // Check the current state BEFORE recovery
    var baseRoundMiner = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // CRITICAL: For UpdateValue behavior, OutValue must be null in current state
    if (baseRoundMiner.OutValue != null && baseRoundMiner.OutValue.Value.Any())
    {
        return false; // Miner has already produced UpdateValue block this round
    }
    
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    return minerInRound.OutValue != null && minerInRound.Signature != null &&
           minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
}
```

**Additional Invariant Checks:**

In `ValidateBeforeExecution`, add behavior-specific validation: [8](#0-7) 

Before calling `RecoverFromUpdateValue`, verify the current state is consistent with the claimed behavior.

**Test Cases:**

1. **Test_UpdateValue_WhenAlreadyMined_ShouldReject**: Verify that attempting a second `UpdateValue` in the same round fails validation
2. **Test_UpdateValue_AfterRoundTransition_ShouldSucceed**: Verify legitimate `UpdateValue` in new round succeeds
3. **Test_ProducedBlocks_Counter_Integrity**: Verify counter cannot be artificially inflated

### Proof of Concept

**Required Initial State:**
- Round R with miner Alice assigned to a time slot
- Alice's `OutValue == null` (hasn't mined yet in round R)

**Attack Sequence:**

**Block N (Legitimate):**
1. Alice calls `GetConsensusCommand` → receives `UpdateValue` behavior (valid)
2. Alice generates consensus extra data with `OutValue_1`
3. Alice produces block N with `UpdateValue` transaction
4. Network validates and accepts block N
5. **State after Block N**: Alice's `OutValue = OutValue_1`, `ProducedBlocks = 1`

**Block N+1 (Malicious):**
1. Alice modifies node software to force `UpdateValue` behavior again
2. Alice generates consensus extra data with `UpdateValue` behavior and new `OutValue_2`
3. Alice produces block N+1 within same round R
4. **Validation Process:**
   - `ValidateBeforeExecution` gets current state: Alice's `OutValue = OutValue_1` (already set)
   - Calls `RecoverFromUpdateValue` → **overwrites** `OutValue` with `OutValue_2` (no check!)
   - `UpdateValueValidationProvider` checks provided round has OutValue → **passes**
   - Time slot validation → **passes** (if within time slot)
5. Network **accepts** block N+1
6. `ProcessUpdateValue` executes → increments `ProducedBlocks` to 2
7. **State after Block N+1**: Alice's `OutValue = OutValue_2`, `ProducedBlocks = 2`

**Expected vs Actual Result:**
- **Expected**: Second `UpdateValue` should be rejected; Alice should use `TinyBlock` behavior or terminate round
- **Actual**: Second `UpdateValue` is accepted; Alice's `ProducedBlocks = 2` (should be 1)

**Success Condition:**
At term end, Alice receives ~2x the mining rewards of other miners who legitimately produced 1 block each, violating the fair distribution invariant.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-20)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L789-812)
```csharp
        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
                    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L835-845)
```csharp
    private long CalculateShares(long producedBlocksCount, long averageProducedBlocksCount)
    {
        if (producedBlocksCount < averageProducedBlocksCount.Div(2))
            // If count < (1/2) * average_count, then this node won't share Basic Miner Reward.
            return 0;

        if (producedBlocksCount < averageProducedBlocksCount.Div(5).Mul(4))
            // If count < (4/5) * average_count, then ratio will be (count / average_count)
            return producedBlocksCount.Mul(producedBlocksCount).Div(averageProducedBlocksCount);

        return producedBlocksCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```
