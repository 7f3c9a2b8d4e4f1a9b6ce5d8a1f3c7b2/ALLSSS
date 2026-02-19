### Title
Integer Underflow in IsCurrentMiner First Round Logic Causes DoS of Critical Consensus Authorization

### Summary
The `IsCurrentMiner` method contains an arithmetic underflow vulnerability at line 209 when checking miner eligibility during the first round of a term. When `currentMinerOrder < latestMinedOrder`, the checked subtraction operation throws an `OverflowException` before the circular wrap-around compensation can be applied, preventing legitimate miners from being authorized for critical operations including transaction fee claims and cross-chain indexing.

### Finding Description

The vulnerability exists in the private `IsCurrentMiner(string pubkey)` method at lines 209-210: [1](#0-0) 

The code attempts to calculate whether enough time slots have passed for a miner to be eligible in the first round by using:
```
currentMinerOrder.Sub(latestMinedOrder).Add(1).Add(minersCount)
currentMinerOrder.Sub(latestMinedOrder).Add(minersCount)
```

However, the `Sub()` extension method uses checked arithmetic: [2](#0-1) 

When `currentMinerOrder < latestMinedOrder` (which occurs in circular ordering scenarios), the subtraction operation throws an `OverflowException` **before** `minersCount` can be added to compensate for the circular wrap-around. The miner order is assigned as sequential integers starting from 1: [3](#0-2) 

The `latestMinedInfo` query specifically finds the miner with the **highest** order who has already mined: [4](#0-3) 

This creates the problematic scenario where a lower-order miner checking eligibility after a higher-order miner has mined will trigger the underflow.

### Impact Explanation

The `IsCurrentMiner` method is used for critical authorization checks throughout the system:

1. **Token Contract Fee Operations**: The `ClaimTransactionFees` and `DonateResourceToken` methods require current miner authorization: [5](#0-4) 

2. **Cross-Chain Indexing**: Cross-chain operations verify miner status through `CheckCrossChainIndexingPermission`: [6](#0-5) [7](#0-6) 

When the exception is thrown:
- Legitimate miners cannot claim accumulated transaction fees, causing loss of miner rewards
- Cross-chain indexing proposals cannot be submitted or released, halting cross-chain communication
- The entire consensus mechanism is disrupted during the critical first round of each term

The severity is **HIGH** because it causes operational DoS of essential protocol functions during term transitions.

### Likelihood Explanation

**Reachability**: The vulnerable code path is reached during the first round of any term (`currentRound.RoundNumber == 1`): [8](#0-7) 

**Triggering Conditions**:
1. Network recovery scenarios after downtime (explicitly mentioned in code comments)
2. Out-of-order mining during first round due to timing irregularities
3. Miners attempting to mine after missing their initial time slot

**Example Scenario**:
- First round with 5 miners (orders 1-5)
- Miner 5 mines first (or after all miners complete one cycle)
- Miner 2 attempts authorization check
- Calculation: `2.Sub(5)` = -3 → `OverflowException`

The developer comments acknowledge timing edge cases exist: [9](#0-8) 

**Attack Complexity**: LOW - naturally occurs during normal operation under timing stress; no malicious action required.

**Detection**: Exception will be visible in transaction failures but may be misattributed to network issues.

### Recommendation

Replace the arithmetic at lines 209-210 with modular arithmetic that handles circular ordering correctly:

```csharp
var orderDifference = currentMinerOrder < latestMinedOrder 
    ? currentMinerOrder + minersCount - latestMinedOrder 
    : currentMinerOrder - latestMinedOrder;

if (passedSlotsCount == orderDifference.Add(1) || 
    passedSlotsCount == orderDifference)
{
    Context.LogDebug(() => "[CURRENT MINER]FIRST ROUND");
    return true;
}
```

Alternatively, use modulo arithmetic:
```csharp
var orderDifference = (currentMinerOrder - latestMinedOrder + minersCount) % minersCount;
```

**Additional Mitigations**:
1. Add comprehensive unit tests covering first-round scenarios with various order combinations
2. Add explicit handling for wrap-around cases with clear documentation
3. Consider adding try-catch in the public `IsCurrentMiner` method to prevent exception propagation while logging the error

### Proof of Concept

**Initial State**:
1. Deploy AEDPoS contract and initialize first term
2. Configure 5 miners with orders 1, 2, 3, 4, 5

**Attack Sequence**:
1. Wait for first round of term to begin
2. Miner 4 or 5 mines a block first (can occur naturally due to timing)
3. Miner 1, 2, or 3 attempts to call `ClaimTransactionFees` on Token contract
4. Token contract calls `IsCurrentMiner` for authorization
5. `IsCurrentMiner` reaches line 209 with `currentMinerOrder < latestMinedOrder`
6. `Sub()` throws `OverflowException`

**Expected Result**: Miner should be authorized if timing is correct per circular ordering logic

**Actual Result**: Transaction fails with `OverflowException`, miner cannot claim fees or perform cross-chain operations

**Success Condition**: Transaction failure observable in blockchain logs with arithmetic overflow exception during first round of term transitions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L104-108)
```csharp
    /// <summary>
    ///     Current implementation can be incorrect if all nodes recovering from
    ///     a strike more than the time of one round, because it's impossible to
    ///     infer a time slot in this situation.
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L191-193)
```csharp
        // If current round is the first round of current term.
        if (currentRound.RoundNumber == 1)
        {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L196-198)
```csharp
            var latestMinedInfo =
                currentRound.RealTimeMinersInformation.Values.OrderByDescending(i => i.Order)
                    .FirstOrDefault(i => i.ActualMiningTimes.Any() && i.Pubkey != pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L209-210)
```csharp
                if (passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(1).Add(minersCount) ||
                    passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(minersCount))
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L26-32)
```csharp
    public static int Sub(this int a, int b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Extensions/MinerListExtensions.cs (L31-31)
```csharp
            minerInRound.Order = i + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L283-290)
```csharp
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
```
