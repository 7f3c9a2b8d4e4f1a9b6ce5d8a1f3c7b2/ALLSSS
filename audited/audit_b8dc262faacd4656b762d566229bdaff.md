### Title
Dictionary Access Without Key Validation in IsCurrentMiner During Miner List Changes Causes KeyNotFoundException

### Summary
The `IsCurrentMiner` function bypasses the dictionary key existence check when `IsMinerListJustChanged` is true, leading to uncaught `KeyNotFoundException` when accessing `RealTimeMinersInformation` dictionary. This occurs when removed miners attempt to call authorization-protected functions during term transitions or miner replacements, causing transaction failures and operational disruption.

### Finding Description

The vulnerability exists in the `IsCurrentMiner(string pubkey)` private method. The root cause is a conditional safety check that only validates dictionary key existence when the miner list has NOT changed: [1](#0-0) 

When `IsMinerListJustChanged` is true, this check is completely bypassed, yet the code proceeds to directly access the dictionary without validation: [2](#0-1) 

The `IsMinerListJustChanged` flag is set to true in two scenarios:

1. When generating the first round of a new term: [3](#0-2) 

2. When replacing evil miners within a term: [4](#0-3) 

The vulnerability is triggered when `ConvertAddressToPubkey` returns a pubkey that exists in the previous round but not in the current round, because it searches BOTH rounds: [5](#0-4) 

Additional vulnerable dictionary accesses exist at:
- Line 182 which calls `ArrangeAbnormalMiningTime`, containing another unguarded access: [6](#0-5) 

- Line 205 using `.Single()` which throws if the key doesn't exist: [7](#0-6) 

The public entry point is called from multiple critical system functions: [8](#0-7) [9](#0-8) [10](#0-9) 

### Impact Explanation

**Operational Impact - Critical DoS:**
- Transaction failures via `KeyNotFoundException` during term transitions and miner replacements
- Affects critical system operations: `ClaimTransactionFees`, `DonateResourceToken`, `ProposeCrossChainIndexing`, `ReleaseCrossChainIndexingProposal`
- Removed miners cannot complete legitimate operations (e.g., claiming accumulated transaction fees from their last blocks)
- System instability during consensus transitions, a regularly occurring event in AEDPoS

**Affected Parties:**
- Removed/replaced miners who need to claim fees or perform cross-chain operations
- The broader network during term transitions when multiple miners may be replaced
- Cross-chain indexing operations become unavailable if executed by recently removed miners

**Severity Justification:**
This is a Critical severity issue because it causes guaranteed transaction failures during normal protocol operation (term changes), affects multiple core system functions, and creates operational disruption without requiring any malicious intent.

### Likelihood Explanation

**Reachable Entry Point:**
Public methods `ClaimTransactionFees`, `DonateResourceToken`, `ProposeCrossChainIndexing`, and `ReleaseCrossChainIndexingProposal` are callable by any miner address and internally invoke `IsCurrentMiner`.

**Feasible Preconditions:**
- Term changes occur regularly in AEDPoS (every `PeriodSeconds`)
- Miner replacements occur when miners miss too many time slots
- No attacker capabilities required - happens during normal operation

**Execution Practicality:**
1. Wait for or trigger a term change/miner replacement (natural protocol behavior)
2. As a removed miner, call `ClaimTransactionFees()` or similar function
3. `IsCurrentMiner` receives pubkey from previous round
4. Safety check at lines 142-144 is bypassed
5. Dictionary access at line 158, 182, or 205 throws `KeyNotFoundException`

**Economic Rationality:**
Zero attack cost - this occurs during legitimate protocol operations. Removed miners may naturally attempt to claim fees they earned before removal.

**Probability:**
High probability during every term transition or miner replacement event, affecting any removed miner who attempts to perform protected operations.

### Recommendation

**Code-Level Mitigation:**

Add explicit key existence validation before all dictionary accesses, regardless of `IsMinerListJustChanged` status:

```csharp
private bool IsCurrentMiner(string pubkey)
{
    if (pubkey == null) return false;
    
    if (!TryToGetCurrentRoundInformation(out var currentRound)) return false;
    
    // Always validate key existence, even during miner list changes
    if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
        return false;
    
    // ... rest of logic
}
```

**Invariant Checks:**
- All dictionary accesses in consensus logic must validate key existence first
- `ConvertAddressToPubkey` should only return pubkeys that exist in the CURRENT round, not previous rounds
- Add defensive checks in `ArrangeAbnormalMiningTime` before accessing the dictionary

**Test Cases:**
1. Test `IsCurrentMiner` with removed miner pubkey when `IsMinerListJustChanged = true`
2. Test `ClaimTransactionFees` called by removed miner during term transition
3. Test cross-chain operations by replaced miners
4. Verify all edge cases during first round of new term

### Proof of Concept

**Required Initial State:**
- Blockchain at term N with active miners [A, B, C, D, E]
- Miner E has accumulated transaction fees
- Term transition occurs, new term N+1 replaces E with new miner F
- Current round has `IsMinerListJustChanged = true`
- Miner E's pubkey exists in previous round but NOT in current round

**Transaction Steps:**
1. Miner E calls `ClaimTransactionFees()` on MultiToken contract
2. MultiToken calls `AssertSenderIsCurrentMiner()`
3. This calls `State.ConsensusContract.IsCurrentMiner.Call(Context.Sender)`
4. AEDPoS contract executes `IsCurrentMiner(Address input)` with E's address
5. `ConvertAddressToPubkey` returns E's pubkey (found in previous round)
6. Private `IsCurrentMiner(string pubkey)` is called with E's pubkey
7. Line 142 check: `!currentRound.IsMinerListJustChanged` evaluates to false (it IS changed)
8. Lines 143-144 safety check is SKIPPED
9. Line 150-155 extra block producer check: E is not the extra block producer, continues
10. Line 158: `currentRound.RealTimeMinersInformation[pubkey]` attempts to access non-existent key

**Expected vs Actual Result:**
- **Expected:** Function returns `false` indicating E is not a current miner, transaction continues with authorization failure message
- **Actual:** `KeyNotFoundException` is thrown, transaction fails with unhandled exception

**Success Condition:**
Transaction fails with `KeyNotFoundException` instead of gracefully returning false or providing a proper authorization error message.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L125-134)
```csharp
    private string ConvertAddressToPubkey(Address address)
    {
        if (!TryToGetCurrentRoundInformation(out var currentRound)) return null;
        var possibleKeys = currentRound.RealTimeMinersInformation.Keys.ToList();
        if (TryToGetPreviousRoundInformation(out var previousRound))
            possibleKeys.AddRange(previousRound.RealTimeMinersInformation.Keys);

        return possibleKeys.FirstOrDefault(k =>
            Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(k)) == address);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L142-144)
```csharp
        if (!currentRound.IsMinerListJustChanged)
            if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
                return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L158-159)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[pubkey];
        var timeSlotStartTime = minerInRound.ExpectedMiningTime;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L204-205)
```csharp
                var currentMinerOrder =
                    currentRound.RealTimeMinersInformation.Single(i => i.Key == pubkey).Value.Order;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L337-341)
```csharp
                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L24-24)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L897-906)
```csharp
    private void AssertSenderIsCurrentMiner()
    {
        if (State.ConsensusContract.Value == null)
        {
            State.ConsensusContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
        }

        Assert(State.ConsensusContract.IsCurrentMiner.Call(Context.Sender).Value, "No permission.");
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```
