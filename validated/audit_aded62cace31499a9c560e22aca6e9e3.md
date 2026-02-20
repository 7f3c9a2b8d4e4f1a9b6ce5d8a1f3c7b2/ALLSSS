# Audit Report

## Title
Non-Evil Miner Replacements Incorrectly Bypass Reward Penalty Calculations

## Summary
The Treasury contract's `RecordMinerReplacement()` method unconditionally marks ALL replacement miners as evil miner replacements, allowing legitimate voluntary replacement miners to bypass performance-based penalty calculations during Basic Miner Reward distribution. This enables miners to strategically replace their public key before anticipated poor performance periods to receive full rewards.

## Finding Description

The vulnerability exists in the Treasury contract's `RecordMinerReplacement()` method. While the function correctly branches on the `IsOldPubkeyEvil` flag to handle different replacement scenarios (transferring mining history for non-evil replacements vs. adding to replacement candidate map for evil miners), it unconditionally sets the penalty bypass flag for ALL replacements regardless of the evil status. [1](#0-0) 

The execution flow begins when a candidate admin voluntarily replaces their public key through the Election contract's `ReplaceCandidatePubkey()` method, which only requires the caller to be the candidate's admin. [2](#0-1) 

This triggers the Election contract's `PerformReplacement()` method, which notifies the AEDPoS consensus contract. [3](#0-2) 

The AEDPoS contract's `RecordCandidateReplacement()` then calls Treasury's `RecordMinerReplacement()` without setting the `IsOldPubkeyEvil` field (defaults to `false` for voluntary replacements). [4](#0-3) 

The protobuf message definition includes the `is_old_pubkey_evil` field specifically to distinguish between evil and non-evil replacements. [5](#0-4) 

During reward distribution, the `UpdateBasicMinerRewardWeights()` function checks the incorrectly-set flag. When true, miners receive shares equal to their produced blocks directly, completely bypassing the penalty calculation. [6](#0-5) 

The `CalculateShares()` function enforces strict performance penalties that replacement miners incorrectly avoid: miners producing less than 50% of average blocks receive zero shares, and those producing 50-80% of average receive quadratic penalties. [7](#0-6) 

## Impact Explanation

This vulnerability breaks the Treasury contract's fundamental invariant of fair, performance-based reward distribution. Replacement miners systematically receive unfair advantages in Basic Miner Reward allocation:

**Severe Underperformance (40% of average blocks):**
- Regular miner: 0 shares (below 50% threshold)
- Replacement miner: 40 shares  
- **Result**: Infinite percentage excess rewards

**Medium Underperformance (60% of average blocks):**
- Regular miner: 36 shares (60² ÷ 100 with quadratic penalty)
- Replacement miner: 60 shares
- **Result**: 67% excess rewards (24 additional shares)

Over multiple terms, this systematically redistributes Basic Miner Rewards from high-performing miners to strategically-timed underperforming replacement miners, undermining the economic incentive structure designed to encourage reliable block production.

## Likelihood Explanation

**Attacker Capability**: Any candidate admin can exploit this vulnerability through the Election contract's public `ReplaceCandidatePubkey()` method, which is a standard operational role for key rotation.

**Attack Complexity**: Low. A single transaction to `ReplaceCandidatePubkey(oldPubkey, newPubkey)` automatically triggers the cross-contract notification chain that incorrectly sets the bypass flag. The next reward distribution period exempts the new key from penalties.

**Economic Rationality**: Strong financial incentive exists. A miner anticipating poor performance (hardware failures, network issues, scheduled maintenance) can replace their public key to receive 40-100% additional reward shares compared to penalty-adjusted rewards. The transaction cost is minimal while the reward benefit can be substantial.

**Preconditions**: Requires being a current candidate with admin privileges, achievable through normal election participation. No governance approvals or rate limits exist on key replacement operations.

## Recommendation

The fix should move the `IsReplacedEvilMiner` flag setting inside the conditional branch, so it only applies to actual evil miner replacements:

```csharp
public override Empty RecordMinerReplacement(RecordMinerReplacementInput input)
{
    Assert(
        Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
        "Only AEDPoS Contract can record miner replacement.");

    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    if (!input.IsOldPubkeyEvil)
    {
        var latestMinedTerm = State.LatestMinedTerm[input.OldPubkey];
        State.LatestMinedTerm[input.NewPubkey] = latestMinedTerm;
        State.LatestMinedTerm.Remove(input.OldPubkey);
    }
    else
    {
        var replaceCandidates = State.ReplaceCandidateMap[input.CurrentTermNumber] ?? new StringList();
        replaceCandidates.Value.Add(input.NewPubkey);
        State.ReplaceCandidateMap[input.CurrentTermNumber] = replaceCandidates;
        
        // Only set bypass flag for evil miner replacements
        State.IsReplacedEvilMiner[input.NewPubkey] = true;
    }

    return new Empty();
}
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up a candidate with admin permissions
2. Call `ReplaceCandidatePubkey` to voluntarily replace the public key
3. Have the replacement miner produce blocks below penalty thresholds (e.g., 40% of average)
4. Trigger reward distribution via `Release()`
5. Verify the replacement miner receives full shares equal to produced blocks
6. Verify a comparable non-replacement miner with same block production receives 0 shares due to penalties

The test would confirm that voluntary replacements incorrectly bypass the `CalculateShares()` penalty logic despite not being evil miner replacements.

## Notes

The existence of the branching logic on `IsOldPubkeyEvil`, combined with the protobuf field definition specifically designed to distinguish replacement types, strongly indicates the unconditional flag setting at line 596 is a bug rather than intended behavior. The design intent appears to be: exempt only evil miner replacements (who join mid-term involuntarily) from penalties, while holding voluntary replacements to normal performance standards.

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L583-596)
```csharp
        if (!input.IsOldPubkeyEvil)
        {
            var latestMinedTerm = State.LatestMinedTerm[input.OldPubkey];
            State.LatestMinedTerm[input.NewPubkey] = latestMinedTerm;
            State.LatestMinedTerm.Remove(input.OldPubkey);
        }
        else
        {
            var replaceCandidates = State.ReplaceCandidateMap[input.CurrentTermNumber] ?? new StringList();
            replaceCandidates.Value.Add(input.NewPubkey);
            State.ReplaceCandidateMap[input.CurrentTermNumber] = replaceCandidates;
        }

        State.IsReplacedEvilMiner[input.NewPubkey] = true;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L802-812)
```csharp
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L835-846)
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
    }
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L149-154)
```csharp
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });
```

**File:** protobuf/treasury_contract.proto (L154-159)
```text
message RecordMinerReplacementInput {
    string old_pubkey = 1;
    string new_pubkey = 2;
    int64 current_term_number = 3;
    bool is_old_pubkey_evil = 4;
}
```
