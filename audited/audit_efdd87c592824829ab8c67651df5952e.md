### Title
GetSideChainBalance Returns Inflated Balance Without Accounting for IndexingFeeDebt

### Summary
The `GetSideChainBalance()` function returns the raw token balance of a side chain's virtual address without deducting pending debts tracked in `ArrearsInfo`. When a side chain enters `INDEXING_FEE_DEBT` status during multi-block indexing, remaining tokens are preserved but become unavailable for indexing operations. This creates an inflated balance view that misrepresents actual available funds, potentially misleading external systems and users about the side chain's operational capacity.

### Finding Description

The vulnerability exists in the balance query flow across multiple files:

**Root Cause:**

`GetSideChainBalance()` directly calls `GetSideChainIndexingFeeDeposit()` which queries the token contract for the virtual address balance, returning the raw amount without any debt consideration. [1](#0-0) [2](#0-1) 

**Why Protections Fail:**

The debt tracking system uses a separate data structure (`ArrearsInfo`) that is not consulted during balance queries. [3](#0-2) [4](#0-3) 

**Critical Execution Path:**

During `IndexSideChainBlockData()`, when indexing multiple blocks and the balance becomes insufficient:

1. Initial blocks are paid normally, depleting the balance
2. When `lockedToken < 0`, the system:
   - Records the full indexing price as arrears (debt)
   - Sets status to `INDEXING_FEE_DEBT`
   - Does NOT transfer the remaining balance (only transfers `indexingFeeAmount` accumulated from successful block payments)
3. Remaining balance is preserved but effectively locked [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

Once in debt status, any future indexing attempts will use `lockedToken = 0` regardless of actual balance, creating more debt. [5](#0-4) 

### Impact Explanation

**Information Disclosure with Operational Consequences:**

When a side chain has balance B and debt D (where D > B), `GetSideChainBalance()` returns B, but the actual available funds for indexing is effectively 0 because:

1. The side chain cannot process new indexing without accumulating additional debt
2. The remaining balance B must be applied toward repaying debt D during recharge operations
3. External systems querying the balance for operational decisions receive misleading information [9](#0-8) 

**Concrete Scenario:**
- Side chain has 2 tokens remaining, 10 tokens in debt
- `GetSideChainBalance()` returns 2
- User/system believes 2 tokens are available for indexing
- Reality: 0 tokens available (chain in debt status), 2 tokens reserved for debt repayment

**Affected Parties:**
- External monitoring systems making decisions based on side chain balance
- Side chain operators assessing operational capacity
- Governance systems evaluating side chain health
- Users planning recharge amounts

**Severity:** HIGH - While not direct fund theft, this creates systemic information asymmetry that can lead to operational failures, incorrect financial planning, and degraded cross-chain functionality.

### Likelihood Explanation

**Attacker Capabilities:** No special privileges required - any miner can trigger this by proposing multi-block indexing when a side chain has low balance.

**Attack Complexity:** LOW
- Normal indexing operations naturally create this state
- Scenario: Side chain with 7 tokens, indexing price 5 tokens/block, indexing 3 blocks simultaneously
  - Block 1: charged 5 tokens, 2 remaining
  - Block 2: insufficient funds, 5 tokens debt recorded, 2 tokens preserved
  - Block 3: 5 more tokens debt recorded
  - Result: balance = 2, debt = 10, status = INDEXING_FEE_DEBT

**Feasibility Conditions:**
- Side chain exists with low balance relative to indexing price
- Multiple blocks indexed in single transaction
- No special permissions or governance actions required

**Detection:** The inflated balance is immediately visible via public view function calls, making it trivially observable but not obviously incorrect without also querying debt.

**Probability:** HIGH - This occurs naturally during normal operations when side chains run low on funds, which is an expected scenario in the system's lifecycle.

### Recommendation

**Code-Level Mitigation:**

Modify `GetSideChainBalance()` to return the effective available balance by deducting pending debt:

```csharp
public override Int64Value GetSideChainBalance(Int32Value input)
{
    var chainId = input.Value;
    var sideChainInfo = State.SideChainInfo[chainId];
    Assert(sideChainInfo != null, "Side chain not found.");
    
    var rawBalance = GetSideChainIndexingFeeDeposit(chainId);
    var totalDebt = sideChainInfo.ArrearsInfo.Values.Sum();
    var availableBalance = Math.Max(0, rawBalance - totalDebt);
    
    return new Int64Value { Value = availableBalance };
}
```

**Alternative Approach:**

Add a new view function `GetSideChainAvailableBalance()` that returns the debt-adjusted balance, while keeping `GetSideChainBalance()` for raw balance queries. Update documentation to clarify the distinction.

**Invariant Checks:**

Add assertion in recharge validation: `Assert(GetSideChainBalance() >= GetSideChainIndexingFeeDebt() after recharge operations to ensure debt is fully covered.

**Test Cases:**

Add test verifying:
1. Multi-block indexing scenario with insufficient balance
2. Verify `GetSideChainBalance()` returns debt-adjusted amount (or 0)
3. Confirm balance + debt queries provide consistent information
4. Validate recharge operations with partial balance remaining

### Proof of Concept

**Initial State:**
- Create side chain with 7 token deposit
- Set indexing price to 5 tokens per block
- Side chain status: ACTIVE

**Transaction Steps:**

1. Propose cross-chain indexing for 3 consecutive side chain blocks
2. Call `ProposeCrossChainIndexing()` with 3 blocks
3. Approve and release the indexing proposal
4. Execute `ReleaseCrossChainIndexingProposal()`

**Execution Flow in IndexSideChainBlockData:**
- Block 1: lockedToken = 7, deduct 5, transfer 5 tokens, lockedToken = 2
- Block 2: lockedToken = 2, deduct 5, lockedToken = -3, record 5 debt, NO transfer
- Block 3: lockedToken = -3, deduct 5, lockedToken = -8, record 5 more debt, NO transfer
- Total transferred: 5 tokens
- Final balance: 7 - 5 = 2 tokens
- Total debt: 10 tokens
- Status: INDEXING_FEE_DEBT

**Expected vs Actual Result:**

Query `GetSideChainBalance(chainId)`:
- **Actual Result:** Returns 2 tokens
- **Expected Result:** Should return 0 tokens (or max(0, balance - debt))

Query `GetSideChainIndexingFeeDebt(chainId)`:
- Returns 10 tokens

**Success Condition:**
The vulnerability is confirmed when `GetSideChainBalance()` returns a positive value while `GetSideChainIndexingFeeDebt()` returns a larger debt amount, and the side chain status is `INDEXING_FEE_DEBT`, demonstrating that the balance query provides an inflated view that doesn't reflect actual available funds for indexing operations.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L81-87)
```csharp
    public override Int64Value GetSideChainBalance(Int32Value input)
    {
        var chainId = input.Value;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null, "Side chain not found.");
        return new Int64Value { Value = GetSideChainIndexingFeeDeposit(chainId) };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L89-99)
```csharp
    public override Int64Value GetSideChainIndexingFeeDebt(Int32Value input)
    {
        var chainId = input.Value;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null, "Side chain not found.");

        return new Int64Value
        {
            Value = sideChainInfo.ArrearsInfo.Values.Sum()
        };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L88-98)
```csharp
    private long GetSideChainIndexingFeeDeposit(int chainId)
    {
        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        var balanceOutput = State.TokenContract.GetBalance.Call(new GetBalanceInput
        {
            Owner = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Symbol = Context.Variables.NativeSymbol
        });

        return balanceOutput.Balance;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L828-830)
```csharp
            var lockedToken = sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt
                ? 0
                : GetSideChainIndexingFeeDeposit(chainId);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L844-855)
```csharp
                lockedToken -= indexingPrice;

                if (lockedToken < 0)
                {
                    // record arrears
                    arrearsAmount += indexingPrice;
                    sideChainInfo.SideChainStatus = SideChainStatus.IndexingFeeDebt;
                }
                else
                {
                    indexingFeeAmount += indexingPrice;
                }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L861-868)
```csharp
            if (indexingFeeAmount > 0)
                TransferDepositToken(new TransferInput
                {
                    To = proposer,
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = indexingFeeAmount,
                    Memo = "Index fee."
                }, chainId);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L870-876)
```csharp
            if (arrearsAmount > 0)
            {
                if (sideChainInfo.ArrearsInfo.TryGetValue(formattedProposerAddress, out var amount))
                    sideChainInfo.ArrearsInfo[formattedProposerAddress] = amount + arrearsAmount;
                else
                    sideChainInfo.ArrearsInfo[formattedProposerAddress] = arrearsAmount;
            }
```

**File:** protobuf/cross_chain_contract.proto (L216-217)
```text
    // creditor and amounts for the chain indexing fee debt 
    map<string, int64> arrears_info = 8;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L206-208)
```csharp
            var originBalance = GetSideChainIndexingFeeDeposit(chainId);
            Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
                "Indexing fee recharging not enough.");
```
