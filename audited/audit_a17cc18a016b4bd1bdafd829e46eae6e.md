### Title
NFT Contract Method Fees Inaccessible on Sidechains with Custom Primary Tokens

### Summary
The NFT contract's `GetMethodFee()` function returns fees denominated in `Context.Variables.NativeSymbol` (always "ELF"), which creates a critical usability issue on sidechains that use custom primary tokens. Users holding only the sidechain's primary token cannot pay NFT method fees because the fee charging fallback logic requires the primary token to already be present in the method fee map, which it is not. [1](#0-0) 

### Finding Description

The root cause exists in how method fees are specified versus how they are charged on sidechains:

**1. Fee Specification:**
The NFT contract's `GetMethodFee()` uses `Context.Variables.NativeSymbol` to specify the fee token symbol, which returns "ELF". [2](#0-1) 

**2. Context.Variables.NativeSymbol Configuration:**
On sidechains, `Context.Variables.NativeSymbol` is configured from `Economic:Symbol` with a default of "ELF". Sidechain configurations do not override this value. [3](#0-2) [4](#0-3) 

**3. Sidechain Token Structure:**
Sidechains have two distinct token concepts: the native token ("ELF" from parent chain) and a chain-specific primary token (e.g., "TE") that users primarily hold for transactions. [5](#0-4) 

**4. Broken Fallback Logic:**
The fee charging mechanism in `ChargeFirstSufficientToken()` attempts to fallback to the primary token, but ONLY if the primary token symbol already exists in the `symbolToAmountMap` built from `GetMethodFee()`. [6](#0-5) 

Since the NFT contract's `GetMethodFee()` returns only "ELF" in the fee map, the primary token "TE" is never added to `symbolToAmountMap`, causing the fallback check `symbolToAmountMap.ContainsKey(primaryTokenSymbol)` to fail.

**5. Fee Map Construction:**
The fee charging flow calls `GetMethodFee()` and converts it to a dictionary that becomes the `symbolToAmountMap`. [7](#0-6) 

### Impact Explanation

**Operational Impact - Medium Severity:**

Users on sidechains with custom primary tokens cannot use the NFT contract's `Create` method or any other fee-bearing methods, even when they have sufficient balance of the sidechain's primary token. This effectively renders the NFT contract non-functional on such sidechains.

**Affected Parties:**
- Sidechain users who hold only the chain's primary token (not cross-chain ELF)
- NFT projects deploying on sidechains with custom economic models
- Sidechain ecosystems that rely on their primary token for all transactions

**Quantified Impact:**
- 100% DoS of NFT functionality for users without ELF tokens
- Forces users to cross-chain transfer ELF just to pay fees, adding friction and costs
- Undermines the purpose of having a sidechain-specific primary token

This does not result in fund theft or inflation, but creates a critical usability barrier that prevents legitimate operations.

### Likelihood Explanation

**High Likelihood:**

The vulnerability manifests under realistic and documented conditions:

1. **Documented Feature**: Sidechains with custom primary tokens are an officially documented feature, as shown in sidechain initialization data providers and cross-chain documentation.

2. **Natural User Behavior**: Users on sidechains naturally acquire and hold the primary token of that chain through normal operations (mining rewards, trading, staking). They may not hold ELF if they haven't performed cross-chain transfers.

3. **No Attacker Required**: This is a functional bug, not an attack scenario. It affects normal users attempting legitimate operations.

4. **Zero Attack Cost**: Users simply attempt to call `Create()` on the NFT contract with their primary token balance.

5. **Widespread Impact**: Affects all system contracts that use `Context.Variables.NativeSymbol` in their `GetMethodFee()` implementations, including Profit, Vote, and other core contracts. [8](#0-7) [9](#0-8) 

### Recommendation

**Primary Fix - Modify GetMethodFee Implementation:**

Update the NFT contract (and other system contracts) to use the primary token symbol instead of native symbol:

```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    if (input.Value == nameof(Create))
    {
        // Get primary token symbol, which falls back to native symbol if not set
        var feeSymbol = State.TokenContract.GetPrimaryTokenSymbol.Call(new Empty()).Value;
        return new MethodFees
        {
            MethodName = input.Value,
            Fees =
            {
                new MethodFee
                {
                    Symbol = feeSymbol,
                    BasicFee = 100_00000000
                }
            }
        };
    }
    return new MethodFees();
}
```

**Alternative Fix - Enhance Fallback Logic:**

Modify `ChargeFirstSufficientToken()` to automatically add the primary token to the charging attempt even if it's not in the original fee map:

```csharp
if (!chargeResult)
{
    var primaryTokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
    // Add primary token with the first symbol's amount if not already present
    if (!symbolToAmountMap.ContainsKey(primaryTokenSymbol) && symbolToAmountMap.Any())
    {
        var firstAmount = symbolToAmountMap.First().Value;
        symbol = primaryTokenSymbol;
        amount = firstAmount;
        existingBalance = GetBalance(fromAddress, symbol);
        existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
        // Attempt to charge
        chargeResult = existingBalance + existingAllowance >= amount;
    }
}
```

**Test Cases to Add:**
1. Sidechain initialization with custom primary token
2. NFT Create operation with only primary token balance (no ELF)
3. Verification that fee is charged from primary token successfully
4. Edge case: User has neither ELF nor primary token (should fail with clear error)

### Proof of Concept

**Initial State:**
1. Sidechain deployed with primary token "TE" (not "ELF")
2. NFT contract deployed on sidechain
3. User has 1000 TE tokens, 0 ELF tokens

**Transaction Steps:**
1. User calls `NFTContract.Create()` with required parameters
2. Pre-execution plugin calls `ChargeTransactionFees()`:
   - Calls `GetMethodFee("Create")` → Returns `{Symbol: "ELF", BasicFee: 100_00000000}`
   - Builds `symbolToAmountMap = {"ELF": 100_00000000}`
   - Calls `ChargeFirstSufficientToken()`:
     - Attempts to charge 100 ELF from user
     - User balance: 0 ELF → Fails
     - Checks fallback: `symbolToAmountMap.ContainsKey("TE")` → False
     - Returns `chargeResult = false`
   - Returns `ChargeTransactionFeesOutput{Success: false, ChargingInformation: "Transaction fee not enough"}`
3. Transaction rejected before execution

**Expected vs Actual:**
- **Expected**: Fee charged from TE balance (primary token), transaction succeeds
- **Actual**: Transaction fails with "Transaction fee not enough" despite sufficient TE balance

**Success Condition for Fix:**
After applying the recommended fix, the same transaction should succeed with 100 TE deducted from the user's balance. [10](#0-9) 

### Notes

This vulnerability affects the broader design pattern used across all AElf system contracts. While the native symbol "ELF" serves as a cross-chain standard, the fee charging infrastructure must properly support sidechains that operate with their own primary tokens as the dominant medium of exchange. The broken fallback logic represents an incomplete implementation of the intended multi-token fee system.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L20-37)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(Create))
            return new MethodFees
            {
                MethodName = input.Value,
                Fees =
                {
                    new MethodFee
                    {
                        Symbol = Context.Variables.NativeSymbol,
                        BasicFee = 100_00000000
                    }
                }
            };

        return new MethodFees();
    }
```

**File:** src/AElf.Blockchains.BasicBaseChain/BasicBaseChainAElfModule.cs (L91-94)
```csharp
        Configure<HostSmartContractBridgeContextOptions>(options =>
        {
            options.ContextVariables[ContextVariableDictionary.NativeSymbolName] =
                newConfig.GetValue("Economic:Symbol", "ELF");
```

**File:** docs-sphinx/tutorials/mainnet.md (L268-283)
```markdown
``` json
{
    "CrossChain": {
        "Grpc": {
            "ParentChainServerPort": 5001,
            "ParentChainServerIp": "your mainchain ip address",
            "ListeningPort": 5011,
        },
        "ParentChainId": "AELF",
        "Economic": {
            "SymbolListToPayTxFee": "WRITE,READ,STORAGE,TRAFFIC",
            "SymbolListToPayRental": "CPU,RAM,DISK,NET"
    }
  }
}
```
```

**File:** test/AElf.Contracts.MultiTokenCrossChainTransfer.Tests/SideChainInitializationDataProvider.cs (L49-74)
```csharp
            NativeTokenInfoData = new TokenInfo
            {
                Symbol = "ELF",
                TokenName = "ELF",
                Decimals = 8,
                TotalSupply = 100_000_000_000_000_000,
                Issuer = address,
                IssueChainId = ParentChainId
            }.ToByteString(),
            ParentChainTokenContractAddress = _chainInitializationOptions.RegisterParentChainTokenContractAddress
                ? _chainInitializationOptions.ParentChainTokenContractAddress
                : null,
            ResourceTokenInfo = new ResourceTokenInfo(),
            ChainPrimaryTokenInfo = new ChainPrimaryTokenInfo
            {
                ChainPrimaryTokenData = new TokenInfo
                {
                    Decimals = 2,
                    IsBurnable = true,
                    Issuer = address,
                    TotalSupply = 1_000_000_000,
                    Symbol = _chainInitializationOptions.Symbol,
                    TokenName = "TEST",
                    IssueChainId = _chainInitializationOptions.ChainId
                }.ToByteString()
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-50)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
        var fee = new Dictionary<string, long>();
        var isSizeFeeFree = false;
        if (methodFees != null)
        {
            isSizeFeeFree = methodFees.IsSizeFeeFree;
        }

        if (methodFees != null && methodFees.Fees.Any())
        {
            fee = GetBaseFeeDictionary(methodFees);
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L732-742)
```csharp
        //For user, if charge failed and delegation is null, priority charge primary token
        if (!chargeResult)
        {
            var primaryTokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
            if (symbolToAmountMap.ContainsKey(primaryTokenSymbol))
            {
                symbol = primaryTokenSymbol;
                existingBalance = GetBalance(fromAddress, symbol);
                existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
            }
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L43-49)
```csharp
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
```

**File:** contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs (L43-49)
```csharp
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L132-141)
```csharp
    public override StringValue GetPrimaryTokenSymbol(Empty input)
    {
        if (string.IsNullOrWhiteSpace(_primaryTokenSymbol) && State.ChainPrimaryTokenSymbol.Value != null)
            _primaryTokenSymbol = State.ChainPrimaryTokenSymbol.Value;

        return new StringValue
        {
            Value = _primaryTokenSymbol ?? Context.Variables.NativeSymbol
        };
    }
```
