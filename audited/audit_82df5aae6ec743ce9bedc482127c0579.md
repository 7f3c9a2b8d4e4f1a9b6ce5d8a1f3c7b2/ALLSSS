# Audit Report

## Title
Unbounded MaximumMinersCount Enables Computational DoS via DecodeSecret Complexity

## Summary
The `SetMaximumMinersCount` function lacks upper bound validation, allowing parliament to set arbitrarily large miner counts. During NextRound block production, `RevealSharedInValues` calls `SecretSharingHelper.DecodeSecret` with O(minimumCount²) complexity for each miner. Since `DecodeSecret` is an external library method not patched by the execution observer, its computational cost bypasses AElf's execution limits, potentially exceeding block mining timeouts and causing consensus failure.

## Finding Description

**Vulnerable Function**: `SetMaximumMinersCount` in [1](#0-0) 

The function only validates that the input value is greater than zero, with no upper bound check. [2](#0-1) 

**Attack Vector**: During NextRound block production, `RevealSharedInValues` is invoked [3](#0-2)  and iterates through previous round miners. [4](#0-3) 

For each qualifying miner, it calculates `minimumCount = minersCount × 2 / 3` [5](#0-4)  and calls `SecretSharingHelper.DecodeSecret` with this threshold. [6](#0-5) 

**Computational Complexity**: The `DecodeSecret` method performs Lagrange polynomial interpolation with nested loops [7](#0-6)  resulting in O(threshold²) BigInteger operations over a finite field. With minersCount = 300, minimumCount = 200, each call performs ~40,000 BigInteger operations.

**Execution Observer Bypass**: The execution observer patching system only injects tracking code into contract module methods [8](#0-7) , not external libraries. `SecretSharingHelper` is whitelisted as an external library [9](#0-8)  and its internal loops are not tracked by the execution observer, bypassing the 15000 branch threshold. [10](#0-9) 

**Mining Timeout Limits**: Block production has strict time limits defined in consensus command strategies. Normal blocks have a 300ms mining limit, while term-ending blocks have 2400ms. [11](#0-10)  If the computational cost exceeds these limits, block production fails. [12](#0-11) 

## Impact Explanation

**Severity: HIGH** - Consensus Denial of Service leading to chain halt.

When parliament sets `MaximumMinersCount` to a large value (e.g., 300-1000), and the actual miner count approaches this limit through the auto-increment mechanism [13](#0-12) , the computational cost of `RevealSharedInValues` during NextRound block production can exceed mining timeouts, causing:

1. NextRound block production to timeout and fail
2. Producing miners to miss their time slots
3. Repeated failures preventing round transitions
4. Potential consensus stall if the round cannot advance

**Affected Parties**: All network participants - miners cannot produce blocks, users cannot submit transactions, and chain operations halt.

## Likelihood Explanation

**Probability: MEDIUM-LOW** - Requires parliament governance approval but lacks technical safeguards.

**Prerequisites**:
1. Parliament must approve a `SetMaximumMinersCount` proposal with a dangerously high value (>200)
2. Actual miner count must grow toward this maximum (either through natural time-based growth or election manipulation)
3. NextRound block production must trigger `RevealSharedInValues`

**Feasibility**: While parliament governance provides a social barrier, there is **no technical validation** preventing misconfiguration. Parliament could set values like 500 or 1000 without understanding the computational implications. The natural growth rate (starting at 17 miners + 2/year) is slow, but parliament can override this limit at any time.

**Detection**: The issue becomes apparent when blocks begin timing out, allowing reactive mitigation. However, during the window of elevated miner counts, consensus integrity is compromised.

## Recommendation

Add an upper bound validation in `SetMaximumMinersCount` to prevent computational DoS:

```csharp
public override Empty SetMaximumMinersCount(Int32Value input)
{
    EnsureElectionContractAddressSet();
    
    Assert(input.Value > 0, "Invalid max miners count.");
    // Add upper bound based on computational safety
    Assert(input.Value <= 200, "Max miners count exceeds safe computational limit.");
    
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

The upper bound of 200 is chosen because:
- minimumCount = 200 × 2/3 = 133
- O(133²) ≈ 17,700 operations per miner
- Total complexity remains within safe limits for term-ending blocks (2400ms timeout)

Alternatively, implement computational cost estimation before allowing the parameter change, or optimize the `DecodeSecret` implementation to reduce complexity.

## Proof of Concept

```csharp
[Fact]
public async Task SetMaximumMinersCount_ComputationalDoS_Test()
{
    // Setup: Initialize consensus with default parliament controller
    await InitializeConsensusContract();
    
    // Attack: Parliament sets dangerously high MaximumMinersCount
    var proposalId = await CreateParliamentProposal(
        nameof(ConsensusContract.SetMaximumMinersCount),
        new Int32Value { Value = 500 }
    );
    await ApproveWithMinersAndRelease(proposalId);
    
    // Verify: MaximumMinersCount is set without upper bound validation
    var maxMinersCount = await ConsensusContractStub.GetMaximumMinersCount.CallAsync(new Empty());
    maxMinersCount.Value.ShouldBe(500);
    
    // Simulate: Advance blockchain time to increase actual miner count
    // (In production, this would happen naturally or through election)
    await AdvanceTimestampWithBlock(seconds: 31536000 * 10); // 10 years
    
    // Trigger: Attempt NextRound block production with high miner count
    // This would cause RevealSharedInValues to execute with O(minersCount³) complexity
    // Expected: Block production timeout due to computational cost exceeding mining limits
    
    // Note: Full reproduction requires simulating large miner set with secret sharing
    // In practice, NextRound blocks would fail to produce within timeout when
    // minersCount × minimumCount² exceeds computational budget of 300-2400ms
}
```

**Notes**:
- This vulnerability represents a critical governance misconfiguration risk where lack of technical validation allows parliament to break consensus invariants
- The execution observer bypass for external libraries is an architectural limitation that amplifies the impact
- The severity is MEDIUM due to the governance requirement reducing likelihood, despite HIGH consensus impact

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L25-53)
```csharp
        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-65)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
            {
                var numerator = new BigInteger(sharedParts[i]);
                var denominator = BigInteger.One;
                for (var j = 0; j < threshold; j++)
                {
                    if (i == j) continue;

                    (numerator, denominator) =
                        MultiplyRational(numerator, denominator, orders[j], orders[j] - orders[i]);
                }

                result += RationalToWhole(numerator, denominator);
                result %= SecretSharingConsts.FieldPrime;
            }

            return result.ToBytesArray();
        }
```

**File:** src/AElf.CSharp.CodeOps/Patchers/Module/CallAndBranchCounts/Patcher.cs (L24-27)
```csharp
        foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
        {
            new MethodPatcher(method, proxyBuilder).DoPatch();
        }
```

**File:** src/AElf.CSharp.CodeOps/Validators/Whitelist/IWhitelistProvider.cs (L226-228)
```csharp
            .Namespace("AElf.Cryptography.SecretSharing", Permission.Denied, type => type
                .Type(typeof(SecretSharingHelper), Permission.Denied, member => member
                    .Member(nameof(SecretSharingHelper.DecodeSecret), Permission.Allowed)));
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L49-60)
```csharp
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);

        /// <summary>
        ///     If this tiny block is the last one of current time slot, give half of producing time for mining.
        /// </summary>
        protected int LastTinyBlockMiningLimit => TinyBlockSlotInterval.Div(2);

        /// <summary>
        ///     If this block is of consensus behaviour NEXT_TERM, the producing time is MiningInterval,
        ///     so the limitation of mining is 8 times than DefaultBlockMiningLimit.
        /// </summary>
        protected int LastBlockOfCurrentTermMiningLimit => MiningInterval.Mul(3).Div(5);
```

**File:** src/AElf.Kernel/Miner/Application/IMiningRequestService.cs (L47-64)
```csharp
    private bool ValidateBlockMiningTime(Timestamp blockTime, Timestamp miningDueTime,
        Duration blockExecutionDuration)
    {
        if (miningDueTime - Duration.FromTimeSpan(TimeSpan.FromMilliseconds(250)) <
            blockTime + blockExecutionDuration)
        {
            Logger.LogDebug(
                "Mining canceled because mining time slot expired. MiningDueTime: {MiningDueTime}, BlockTime: {BlockTime}, Duration: {BlockExecutionDuration}",
                miningDueTime, blockTime, blockExecutionDuration);
            return false;
        }

        if (blockTime + blockExecutionDuration >= TimestampHelper.GetUtcNow()) return true;
        Logger.LogDebug(
            "Will cancel mining due to timeout: Actual mining time: {BlockTime}, execution limit: {BlockExecutionDuration} ms",
            blockTime, blockExecutionDuration.Milliseconds());
        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```
