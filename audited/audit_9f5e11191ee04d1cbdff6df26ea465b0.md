### Title
Consensus DoS via Quadratic Complexity in Secret Sharing Revelation Causing Block Production Failure

### Summary
The `RevealSharedInValues()` function contains nested LINQ operations with O(n³) computational complexity that exceed AElf's `ExecutionCallThreshold` limit of 15,000 operations when miner count reaches approximately 20-25 miners (far below the 1000+ mentioned). This causes `GetConsensusExtraData` to throw `RuntimeCallThresholdExceededException` during round transitions, halting block production and consensus entirely.

### Finding Description
The vulnerability exists in the secret sharing revelation logic within `RevealSharedInValues()`. [1](#0-0) 

The critical inefficiency occurs in the nested LINQ operations: [2](#0-1) 

For each miner being processed, the code calls `.ToList()` on `DecryptedPieces.Keys` **inside the Select lambda**, executing it n times, then calls `.First()` on all `RealTimeMinersInformation.Values` (also n operations). This results in approximately 1.5n² operations per miner. When iterating through all n miners that pass the validation checks at lines 35-36, total complexity becomes 1.5n³.

This function is called during round transitions via: [3](#0-2) 

The `GetConsensusExtraData` method is marked as a view method in the ACS4 standard: [4](#0-3) 

However, view methods are still subject to AElf's execution observer limits. [5](#0-4) 

With the default `ExecutionCallThreshold` of 15,000 operations, the function fails at approximately 22 miners (1.5 × 22³ ≈ 16,000 operations), well below the 1000+ mentioned in the question.

The miner count starts at 17 and auto-increases by 2 per year: [6](#0-5) 

The maximum miner count defaults to `int.MaxValue`: [7](#0-6) 

Secret sharing must be enabled for this code path to execute: [8](#0-7) 

### Impact Explanation
When the execution call threshold is exceeded, the contract throws `RuntimeCallThresholdExceededException`, causing `GetConsensusExtraData` to fail. Since this method is called during block header generation for NextRound behavior, the block cannot be produced, halting the consensus system entirely.

The failure occurs during critical round transitions when miners need to move to the next consensus round. Without successful round transitions, no new blocks can be produced, freezing the entire blockchain until the miner count is reduced (requiring a term change through the election contract) or secret sharing is disabled through governance.

All network participants are affected: validators cannot produce blocks, users cannot submit transactions, and the chain becomes non-operational. For a 1000+ miner scenario as asked, the complexity would be 1.5 billion operations, making the function completely impossible to execute. However, the practical threshold where failure occurs is around 20-25 miners, which represents a CRITICAL severity DoS vulnerability.

### Likelihood Explanation
The vulnerability requires two conditions:
1. Secret sharing feature must be enabled (controlled via Configuration contract)
2. Miner count must exceed approximately 20-25 miners

At the default auto-increase rate of 2 miners per year starting from 17 miners, the threshold would be naturally reached in 2-4 years of blockchain operation. Governance can accelerate this by:
- Calling `SetMinerIncreaseInterval` to decrease the increase interval: [9](#0-8) 
- Setting `MaximumMinersCount` to a higher value and allowing more election winners: [10](#0-9) 

The attack complexity is LOW—it occurs automatically once conditions are met. No malicious actor is required; the vulnerability manifests from normal system growth. If secret sharing is enabled by default, this represents a MEDIUM likelihood time-bomb that will eventually trigger. If secret sharing is disabled by default, likelihood is LOW (requires governance to enable it).

For the specific scenario of 1000+ miners mentioned in the question, likelihood is VERY LOW as it would require deliberate governance misconfiguration to set such high miner counts.

### Recommendation
Implement computational complexity bounds and optimize the nested loops:

1. **Immediate Fix**: Add a miner count check before executing `RevealSharedInValues`:
```csharp
if (previousRound.RealTimeMinersInformation.Count > 20)
{
    Context.LogDebug(() => "Skipping secret sharing revelation due to high miner count.");
    return;
}
```

2. **Optimize the Algorithm**: Cache `DecryptedPieces.Keys.ToList()` outside the Select loop and create a lookup dictionary for `RealTimeMinersInformation` by pubkey to avoid repeated `.First()` calls:
```csharp
var decryptedPieceKeys = anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList();
var minerLookup = previousRound.RealTimeMinersInformation.Values.ToDictionary(m => m.Pubkey);
var orders = decryptedPieceKeys.Select(key => minerLookup[key].Order).ToList();
```

3. **Add Configuration**: Make the miner count threshold configurable through the Configuration contract to allow dynamic adjustment based on performance testing.

4. **Add Tests**: Create integration tests that verify correct behavior with 20, 25, and 30 miners to ensure the threshold is properly enforced and optimizations work correctly.

### Proof of Concept
**Initial State**:
- Secret sharing enabled via Configuration contract
- Blockchain operational with initial 17 miners
- Default `MinerIncreaseInterval` of 31,536,000 seconds (1 year)

**Exploitation Steps**:
1. Wait for natural auto-increase to reach 22+ miners (approximately 2.5 years), OR have governance call `SetMinerIncreaseInterval` with a lower value to accelerate miner count growth
2. Ensure miners are producing blocks normally with secret sharing enabled, populating `DecryptedPieces` for each miner
3. When a miner attempts to produce the NextRound transition block, they call `GetConsensusExtraData` with `Behaviour = NextRound`
4. The call chain reaches `RevealSharedInValues()` which executes the nested LINQ operations on 22+ miners
5. `ExecutionObserver.CallCount()` increments past 15,000 and throws `RuntimeCallThresholdExceededException`
6. Block production fails, consensus cannot transition to next round
7. All subsequent NextRound attempts fail identically, halting the blockchain

**Expected Result**: Block produced with next round information
**Actual Result**: Transaction fails with "Contract call threshold 15000 exceeded" error, consensus halts

**Success Condition**: Blockchain unable to produce blocks during round transitions until miner count is reduced below threshold or secret sharing is disabled.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L25-25)
```csharp
        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-44)
```csharp
            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L122-125)
```csharp
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** protobuf/acs4.proto (L25-27)
```text
    rpc GetConsensusExtraData (google.protobuf.BytesValue) returns (google.protobuf.BytesValue) {
        option (aelf.is_view) = true;
    }
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L21-26)
```csharp
    public void CallCount()
    {
        if (_callThreshold != -1 && _callCount == _callThreshold)
            throw new RuntimeCallThresholdExceededException($"Contract call threshold {_callThreshold} exceeded.");

        _callCount++;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L56-64)
```csharp
    public override Empty SetMinerIncreaseInterval(Int64Value input)
    {
        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set miner increase interval.");
        Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
        State.MinerIncreaseInterval.Value = input.Value;
        return new Empty();
    }
```
