### Title
Incorrect Accounting Assertion in Recharge() Causes Denial of Service for Valid Side Chain Recharges

### Summary
The `Recharge()` function contains a critical logic error in its assertion at line 207 that validates whether sufficient funds have been provided to clear arrears and maintain minimum balance. The assertion incorrectly counts both `input.Amount` and `arrearsAmount` twice in its calculation, creating an overly restrictive check that requires approximately double the actual needed amount. This causes legitimate recharge transactions to be wrongly rejected, preventing side chains in debt status from being reactivated.

### Finding Description

The vulnerability is located in the `Recharge()` function in `contract/AElf.Contracts.CrossChain/CrossChainContract.cs`. [1](#0-0) 

**Root Cause:**

The function follows this execution flow:
1. User transfers `input.Amount` to the side chain's virtual address [2](#0-1) 
2. If the side chain is in debt, the function loops through `ArrearsInfo` and transfers arrears to proposers [3](#0-2) 
3. After transfers complete, it retrieves the remaining balance [4](#0-3) 
4. It then validates with: `Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice)` [5](#0-4) 

**The Problem:**

At line 206, `originBalance` is retrieved AFTER the arrears have been transferred out, so it equals: `old_balance + input.Amount - arrearsAmount`

The assertion at line 207 becomes:
```
input.Amount + (old_balance + input.Amount - arrearsAmount) >= arrearsAmount + IndexingPrice
```

Simplifying:
```
old_balance + 2*input.Amount - arrearsAmount >= arrearsAmount + IndexingPrice
old_balance + 2*input.Amount >= 2*arrearsAmount + IndexingPrice
```

**What it SHOULD be:**

After recharge and paying arrears, the remaining balance must be at least `IndexingPrice`:
```
old_balance + input.Amount - arrearsAmount >= IndexingPrice
```

Or equivalently:
```
old_balance + input.Amount >= arrearsAmount + IndexingPrice
```

Since `originBalance = old_balance + input.Amount - arrearsAmount`, the correct check should be:
```
originBalance >= IndexingPrice
```

The bug causes the assertion to require approximately double the necessary funds.

### Impact Explanation

**Operational Impact - Denial of Service:**

Legitimate users attempting to recharge side chains in debt status will be incorrectly rejected when they provide exactly the required amount. This prevents side chains from being reactivated after falling into `IndexingFeeDebt` status.

**Concrete Example:**
- Side chain virtual address balance: 75 tokens
- Total arrears owed to proposers: 100 tokens
- Indexing price requirement: 50 tokens
- User provides: 75 tokens (exactly enough)

**Expected behavior:** Should succeed
- Total available: 75 + 75 = 150 tokens
- After paying arrears: 150 - 100 = 50 tokens
- Remaining (50) >= IndexingPrice (50) ✓

**Actual behavior:** Transaction fails
- Assertion checks: `75 + 50 >= 100 + 50` → `125 >= 150` ✗

**Who is affected:**
- Side chain creators attempting to clear debt
- Side chain operators trying to maintain service
- Users of side chains stuck in debt status

The severity is HIGH because it completely blocks a critical recovery mechanism for debt-ridden side chains, with no workaround except overpaying by approximately double the required amount.

### Likelihood Explanation

**Reachable Entry Point:**
The `Recharge()` function is a public entry point callable by any user. [6](#0-5) 

**Feasible Preconditions:**
1. A side chain must exist and be in `IndexingFeeDebt` status (occurs naturally when indexing fees deplete the locked balance) [7](#0-6) 
2. User must have token allowance for the recharge amount
3. Side chain must have accumulated arrears [8](#0-7) 

**Execution Practicality:**
This bug triggers automatically in normal operation whenever a side chain falls into debt and someone tries to recharge with the mathematically correct amount. No special attack is needed - it's a logic error that affects legitimate usage.

**Probability:**
HIGH - The bug will manifest every time a recharge is attempted with an amount that is sufficient but not double the requirement. Given the economic incentive to minimize capital lockup, users will naturally attempt to recharge with the minimum required amount, triggering this bug frequently.

### Recommendation

**Fix the assertion at line 207:**

Change from:
```csharp
Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
    "Indexing fee recharging not enough.");
```

To:
```csharp
Assert(originBalance >= sideChainInfo.IndexingPrice,
    "Indexing fee recharging not enough.");
```

**Rationale:**
Since `originBalance` is retrieved after arrears transfers have completed, it already represents the post-arrears balance. The check only needs to verify that this remaining balance meets the minimum indexing price requirement.

**Additional validation:**
The existing transfers at lines 197-203 already implicitly validate that `old_balance + input.Amount >= arrearsAmount` (they would fail otherwise). The assertion only needs to confirm the remaining balance is sufficient.

**Test cases to add:**
1. Recharge with exact minimum amount (arrears + indexing price - old balance)
2. Recharge with old_balance = 0, verifying minimum required is (arrears + indexing price)
3. Recharge with partial old_balance, verifying correct calculation
4. Edge case: recharge where old_balance > arrears (should not require any input amount if old_balance - arrears >= indexing price)

### Proof of Concept

**Initial State:**
- Side chain ID: 12345
- Side chain status: `IndexingFeeDebt`
- Virtual address balance: 75 tokens
- Arrears info: {proposer1: 100 tokens}
- Indexing price: 50 tokens

**Transaction Sequence:**

1. User approves CrossChainContract to spend 75 tokens
2. User calls `Recharge(chainId: 12345, amount: 75)`

**Expected Result:**
Transaction succeeds because:
- Virtual balance after user transfer: 75 + 75 = 150
- After paying 100 to proposer1: 150 - 100 = 50
- Remaining balance (50) >= IndexingPrice (50) ✓
- Side chain status changed to `Active`
- ArrearsInfo cleared

**Actual Result:**
Transaction fails at line 207 with error "Indexing fee recharging not enough" because:
- Virtual balance after transfers: 50
- Assertion evaluates: `75 + 50 >= 100 + 50` → `125 >= 150` ✗

**Workaround (demonstrating the bug):**
User must provide ~150 tokens instead of 75 to pass the incorrect assertion, effectively paying double the required amount.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L174-215)
```csharp
    public override Empty Recharge(RechargeInput input)
    {
        var chainId = input.ChainId;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null && sideChainInfo.SideChainStatus != SideChainStatus.Terminated,
            "Side chain not found or incorrect side chain status.");

        TransferFrom(new TransferFromInput
        {
            From = Context.Sender,
            To = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Symbol = Context.Variables.NativeSymbol,
            Amount = input.Amount,
            Memo = "Indexing fee recharging."
        });

        long arrearsAmount = 0;
        if (sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt)
        {
            // arrears
            foreach (var arrears in sideChainInfo.ArrearsInfo)
            {
                arrearsAmount += arrears.Value;
                TransferDepositToken(new TransferInput
                {
                    To = Address.Parser.ParseFrom(ByteString.FromBase64(arrears.Key)),
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = arrears.Value,
                    Memo = "Indexing fee recharging."
                }, chainId);
            }

            var originBalance = GetSideChainIndexingFeeDeposit(chainId);
            Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
                "Indexing fee recharging not enough.");
        }

        sideChainInfo.ArrearsInfo.Clear();
        sideChainInfo.SideChainStatus = SideChainStatus.Active;
        State.SideChainInfo[chainId] = sideChainInfo;
        return new Empty();
    }
```

**File:** protobuf/cross_chain_contract.proto (L189-199)
```text
enum SideChainStatus
{
    // Currently no meaning.
    FATAL = 0;
    // The side chain is being indexed.
    ACTIVE = 1;
    // The side chain is in debt for indexing fee.
    INDEXING_FEE_DEBT = 2;
    // The side chain is disposed.
    TERMINATED = 3;
}
```

**File:** protobuf/cross_chain_contract.proto (L216-217)
```text
    // creditor and amounts for the chain indexing fee debt 
    map<string, int64> arrears_info = 8;
```
