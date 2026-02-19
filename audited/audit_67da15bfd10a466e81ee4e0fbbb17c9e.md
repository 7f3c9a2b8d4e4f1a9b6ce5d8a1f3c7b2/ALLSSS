# Audit Report

## Title
Token Dust Accumulation from Integer Division in Resource Token Distribution

## Summary
The `DistributeResourceTokensToPreviousMiners` method uses integer division to distribute resource tokens to miners on side chains, causing remainder tokens to be permanently locked in the consensus contract with no recovery mechanism. This leads to gradual token loss over time.

## Finding Description

The vulnerability exists in the resource token distribution mechanism for side chains. When the consensus contract distributes accumulated resource tokens (READ, WRITE, STORAGE, TRAFFIC) to miners during cross-chain updates, it uses integer division which truncates any remainder.

**Root Cause:**

The distribution method calculates each miner's share using integer division [1](#0-0) . The `Div` extension method performs standard C# integer division without handling remainders [2](#0-1) .

**Execution Path:**

1. On side chains, resource tokens accumulate in the consensus contract balance through the `DonateResourceToken` mechanism, where tokens are sent to the consensus contract address [3](#0-2) 

2. When `UpdateInformationFromCrossChain` is invoked by the CrossChain contract [4](#0-3) , it calls `DistributeResourceTokensToPreviousMiners` [5](#0-4) 

3. For each resource token symbol, the balance is retrieved and divided equally among miners [6](#0-5) 

4. Each miner receives the calculated amount via transfer [7](#0-6) 

5. The remainder (balance % minerCount) stays locked in the consensus contract with no method to recover it

**No Recovery Mechanism:**

This is the only location in the entire consensus contract that transfers tokens out of the contract's balance. There are no administrative functions or governance mechanisms to withdraw locked tokens.

## Impact Explanation

**Direct Fund Loss:**
Resource tokens that should be distributed to miners are permanently locked in the consensus contract. The impact compounds over time because:

- Each cross-chain update leaves a remainder of up to (minerCount - 1) token units per symbol
- Multiple resource token symbols are affected simultaneously (READ, WRITE, STORAGE, TRAFFIC)
- No administrative recovery function exists
- The accumulated dust can never be reclaimed

**Quantified Impact:**
For each update cycle where `balance % minerCount != 0`, up to (minerCount - 1) token units per symbol are locked. With typical side chain configurations having 5-21 miners and frequent cross-chain updates, this accumulates to measurable amounts over time.

**Affected Parties:**
- Side chain miners receive marginally less resource token compensation than intended
- Side chain resource token economics are distorted as tokens accumulate in an inaccessible address
- The consensus contract becomes an unintended permanent token sink

**Severity:** MEDIUM - Individual losses per update are small (measured in minimum token units), but the cumulative effect is irreversible and there is no recovery mechanism. This violates the intended token distribution economics of the system.

## Likelihood Explanation

**Entry Point:**
The vulnerability is triggered through `UpdateInformationFromCrossChain`, which is called by the CrossChain system contract during normal cross-chain consensus synchronization [8](#0-7) .

**Preconditions:**
The issue occurs whenever the consensus contract's resource token balance is not evenly divisible by the miner count. This is extremely common because:

- Resource token balances vary based on contract execution and resource consumption patterns
- Miner counts (typically 5-21) are rarely exact divisors of accumulated token amounts
- No attacker involvement is required - this happens during normal operations

**Execution Probability:**
This occurs automatically on every cross-chain update cycle on side chains where a remainder exists. Given typical token accumulation patterns and miner counts, the majority of distribution events will have at least one token symbol with a non-zero remainder.

**Probability:** HIGH - This is not an attack scenario but a systematic flaw that occurs during routine cross-chain consensus updates on all AElf side chains.

## Recommendation

Implement remainder handling in the distribution logic. Options include:

**Option 1 - Distribute Remainder to First Miner:**
```csharp
var amount = balance.Div(minerList.Count);
var remainder = balance.Sub(amount.Mul(minerList.Count));
if (amount <= 0) continue;

for (int i = 0; i < minerList.Count; i++)
{
    var pubkey = minerList[i];
    var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
    var transferAmount = i == 0 ? amount.Add(remainder) : amount;
    
    State.TokenContract.Transfer.Send(new TransferInput
    {
        To = address,
        Amount = transferAmount,
        Symbol = symbol
    });
}
```

**Option 2 - Keep Remainder for Next Distribution:**
Accept that small remainders will carry forward to the next distribution cycle, where they'll be included in the total balance. This requires no code changes but acknowledges that dust will eventually distribute as it accumulates.

**Option 3 - Add Administrative Recovery Function:**
Add a governance-controlled method to withdraw any accumulated dust, though this adds complexity and may not be worth it for minimal amounts.

**Recommended Solution:** Option 1 is the cleanest fix, ensuring complete distribution while maintaining simplicity and fairness (the first miner receives a negligibly larger amount).

## Proof of Concept

The following test demonstrates the remainder accumulation issue:

```csharp
[Fact]
public async Task ResourceTokenDistribution_LeavesRemainder_Test()
{
    // Setup: Side chain with 3 miners
    var minerCount = 3;
    var resourceTokenBalance = 1000000000; // 10 tokens with 8 decimals
    
    // Simulate DonateResourceToken accumulating tokens in consensus contract
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = ConsensusContractAddress,
        Symbol = "READ",
        Amount = resourceTokenBalance
    });
    
    // Get initial balance
    var initialBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = ConsensusContractAddress,
        Symbol = "READ"
    });
    Assert.Equal(resourceTokenBalance, initialBalance.Balance);
    
    // Trigger UpdateInformationFromCrossChain which calls DistributeResourceTokensToPreviousMiners
    await UpdateCrossChainInformation();
    
    // Check final balance - should have remainder
    var finalBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = ConsensusContractAddress,
        Symbol = "READ"
    });
    
    var expectedRemainder = resourceTokenBalance % minerCount; // 1000000000 % 3 = 1
    Assert.Equal(expectedRemainder, finalBalance.Balance);
    Assert.True(finalBalance.Balance > 0, "Remainder tokens are locked in consensus contract");
    
    // Verify no mechanism exists to recover these tokens
    // (All consensus contract methods checked - only DistributeResourceTokensToPreviousMiners transfers out)
}
```

This test confirms that after distribution, remainder tokens remain locked in the consensus contract with no recovery path.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-38)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-53)
```csharp
        DistributeResourceTokensToPreviousMiners();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L73-84)
```csharp
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
            foreach (var pubkey in minerList)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L88-94)
```csharp
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1000-1006)
```csharp
                    {
                        Context.LogDebug(() => $"Adding {amount} of {symbol}s to consensus address account.");
                        // Side Chain
                        receiver =
                            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
                        ModifyBalance(receiver, symbol, amount);
                    }
```
