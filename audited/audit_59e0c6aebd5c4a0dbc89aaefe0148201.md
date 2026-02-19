### Title
Incorrect Recharge Validation Allows Side Chain Reactivation with Insufficient Funds

### Summary
The `Recharge()` function contains a flawed validation formula that double-counts the deposited amount, allowing a side chain in debt to be reactivated with only half the required indexing fee. This enables attackers to clear arrears and change the status to Active while leaving insufficient balance for future indexing operations, leading to immediate re-entry into debt status.

### Finding Description

The vulnerability exists in the `Recharge()` function's validation logic. [1](#0-0) 

The function executes the following sequence:
1. Transfers `input.Amount` from sender to the side chain's virtual address
2. If status is `IndexingFeeDebt`, loops through arrears and transfers each debt amount from the virtual address to creditors [2](#0-1) 
3. Gets the remaining balance AFTER paying arrears
4. Validates: `input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice`
5. Unconditionally clears arrears and sets status to Active [3](#0-2) 

**Root Cause**: The assertion at line 207-208 retrieves `originBalance` AFTER the arrears have been paid from the virtual address. [4](#0-3) 

This means `originBalance = initial_balance + input.Amount - arrearsAmount`.

The validation becomes:
```
input.Amount + (initial_balance + input.Amount - arrearsAmount) >= arrearsAmount + IndexingPrice
2*input.Amount + initial_balance >= 2*arrearsAmount + IndexingPrice
```

When `initial_balance = 0`, this simplifies to:
```
input.Amount >= arrearsAmount + IndexingPrice/2
```

The attacker only needs to pay arrears plus HALF of the indexing price, not the full amount.

### Impact Explanation

**Direct Fund Impact**: 
- Users lose tokens when recharging without achieving proper functionality
- A recharge of 250 tokens passes validation when 300 tokens are actually required (for 200 in arrears + 100 IndexingPrice)
- The side chain is left with only 50 tokens when 100 is needed for indexing
- The next indexing attempt immediately puts the chain back into debt [5](#0-4) 

**Operational Impact**:
- False reactivation: status changes to Active but chain cannot sustain operations
- Waste of recharge funds: depositor loses tokens without restoring functionality
- Immediate re-entry into `IndexingFeeDebt` status on next indexing operation

**Affected Parties**:
- Side chain operators who recharge expecting full functionality restoration
- Indexers who cannot collect proper fees on subsequent indexing
- The integrity of the cross-chain indexing system

### Likelihood Explanation

**Reachable Entry Point**: The `Recharge()` function is publicly callable with only basic authorization checks. [6](#0-5) 

**Feasible Preconditions**:
- Side chain must have `IndexingFeeDebt` status (occurs naturally when locked tokens are depleted)
- Attacker needs tokens for recharge (reasonable assumption for any user)
- No special privileges required

**Execution Practicality**:
- Straightforward transaction: call `Recharge()` with calculated underpayment amount
- Validation flaw triggers automatically without complex manipulation
- Works under normal AElf contract execution model

**Economic Rationality**:
- High probability: the flaw affects any legitimate recharge attempt
- Natural occurrence when users attempt minimum viable recharge
- Cost is reasonable (standard transaction fee)

### Recommendation

**Code-Level Mitigation**:
Replace the validation at line 207-208 with a check AFTER arrears payment:

```csharp
var originBalance = GetSideChainIndexingFeeDeposit(chainId);
Assert(originBalance >= sideChainInfo.IndexingPrice,
    "Insufficient balance after paying arrears.");
```

Alternatively, validate BEFORE paying arrears:
```csharp
var currentBalance = GetSideChainIndexingFeeDeposit(chainId);
Assert(input.Amount + currentBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
    "Indexing fee recharging not enough.");
// Then proceed to pay arrears
```

**Invariant to Enforce**:
After recharge completion, `GetSideChainIndexingFeeDeposit(chainId) >= sideChainInfo.IndexingPrice` must hold.

**Test Case**:
Add test verifying that recharge with `arrears + IndexingPrice/2` tokens fails validation when initial balance is zero.

### Proof of Concept

**Initial State**:
- Side chain status: `IndexingFeeDebt`
- Virtual address balance: 0 tokens
- Total arrears: 200 tokens (owed to creditor)
- IndexingPrice: 100 tokens
- Required recharge: 300 tokens (200 + 100)

**Attack Steps**:
1. Attacker calls `Recharge()` with `amount = 250` tokens (underpayment of 50)
2. Function transfers 250 to virtual address → balance = 250
3. Loop pays 200 to creditors → balance = 50
4. `originBalance = GetSideChainIndexingFeeDeposit(chainId)` returns 50
5. Validation: `250 + 50 >= 200 + 100` → `300 >= 300` ✓ PASSES
6. ArrearsInfo cleared, status set to Active

**Expected Result**: Transaction should FAIL because 250 < 300

**Actual Result**: 
- Transaction succeeds
- Status changed to Active  
- Balance = 50 tokens (insufficient for IndexingPrice of 100)
- Next indexing operation will immediately revert to debt status

**Success Condition**: The side chain achieves Active status with `balance < IndexingPrice`, violating the economic invariant required for sustainable indexing operations.

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L844-851)
```csharp
                lockedToken -= indexingPrice;

                if (lockedToken < 0)
                {
                    // record arrears
                    arrearsAmount += indexingPrice;
                    sideChainInfo.SideChainStatus = SideChainStatus.IndexingFeeDebt;
                }
```
