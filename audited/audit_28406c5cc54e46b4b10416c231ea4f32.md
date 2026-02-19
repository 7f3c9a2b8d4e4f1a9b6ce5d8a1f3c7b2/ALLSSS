### Title
Side Chain Rental Payment Bypass via Missing Creator Assertion

### Summary
The `PayRental()` function silently returns when `SideChainCreator` is null instead of asserting its existence. Since side chain initialization through `InitializeFromParentChain()` requires governance approval and is not automatically enforced, a side chain can operate indefinitely without setting a creator, permanently evading rental payments for parent chain resources.

### Finding Description

The vulnerability exists in the `PayRental()` function where a null creator check returns silently: [1](#0-0) 

The `PayRental()` function is called automatically every block via `DonateResourceToken()`: [2](#0-1) 

`DonateResourceToken()` is invoked by the system transaction generator on every block: [3](#0-2) 

The `SideChainCreator` is only set when `InitializeFromParentChain()` is called: [4](#0-3) 

However, `InitializeFromParentChain()` requires Parliament governance approval and is not automatically enforced at side chain genesis: [5](#0-4) 

The `SetSideChainCreator()` method only allows setting the creator once and requires special permissions: [6](#0-5) 

**Root Cause:** The silent return allows a misconfigured side chain to bypass the rental payment mechanism entirely. Once the side chain starts producing blocks without initialization, `DonateResourceToken()` executes successfully every block, but `PayRental()` skips all rental logic, leaving `OwningRental` and rental charges permanently unprocessed.

### Impact Explanation

**Direct Economic Loss:**
- Side chains are designed to pay rental fees for resources (CPU, RAM, DISK, NET) based on `ResourceAmount` and `Rental` rates per minute
- When creator is null, the entire rental calculation loop is bypassed: [7](#0-6) 

- The side chain receives free resource usage without contributing to the parent chain consensus contract
- This breaks the economic model where side chains must pay for parent chain security and infrastructure

**Affected Parties:**
- Parent chain loses rental revenue that should fund consensus participants
- Properly initialized side chains face unfair competition from free-riding chains
- The protocol's economic incentive structure is undermined

**Severity:** HIGH (protocol specifies Medium, but impact suggests HIGH due to permanent rental evasion enabling unbounded economic loss over the side chain's lifetime)

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to deploy a side chain on the parent chain (via CrossChain contract)
- Ability to prevent or delay Parliament governance proposal for `InitializeFromParentChain()`
- No special cryptographic capabilities needed

**Attack Complexity:**
- LOW - Simply never submit or approve the initialization proposal
- The side chain functions normally for all other operations
- No sophisticated exploit technique required

**Feasibility Conditions:**
- Side chain governance is controlled or compromised
- Side chain operators deliberately skip initialization
- Misconfiguration during deployment

**Detection Constraints:**
- The side chain appears functional and processes transactions normally
- `DonateResourceToken()` succeeds every block without errors
- No on-chain signals indicate rental payment failure
- Only off-chain monitoring of rental payments would detect this

**Probability:** MEDIUM - Requires deliberate misconfiguration or governance failure during side chain setup, but once established, the exploit is automatic and permanent with no recovery mechanism for retroactive rental collection.

### Recommendation

**Immediate Fix:**
Replace the silent return with an assertion in `PayRental()`:

```csharp
var creator = State.SideChainCreator.Value;
Assert(creator != null, "Side chain creator must be initialized before rental payment");
```

This forces `DonateResourceToken()` to fail if the side chain is not properly initialized, preventing block production until initialization is completed.

**Additional Safeguards:**

1. Add initialization check in `DonateResourceToken()` before calling `PayRental()`: [8](#0-7) 

2. Enforce initialization during side chain genesis or first block production

3. Add a view method to query side chain initialization status for monitoring

**Test Cases to Add:**
- Verify `DonateResourceToken()` fails on side chain before `InitializeFromParentChain()` is called
- Confirm rental is calculated correctly after proper initialization
- Test that re-initialization is prevented after successful setup

### Proof of Concept

**Initial State:**
1. Side chain is created on parent chain via CrossChain contract
2. Side chain node starts and begins block production
3. Token contract is deployed but `InitializeFromParentChain()` is never called via governance
4. `State.SideChainCreator.Value` remains null
5. Treasury contract does not exist (indicates side chain via `isMainChain = false` check)

**Exploitation Steps:**

1. **Block N:** Miner produces block, system generates `DonateResourceToken()` transaction
   - Transaction reaches line 915: `AssertSenderIsCurrentMiner()` passes
   - Transaction reaches line 947: `!isMainChain` condition is true
   - Transaction calls `PayRental()` at line 949
   - Line 1021: `creator = State.SideChainCreator.Value` retrieves null
   - Line 1022: Function returns immediately
   - Transaction completes successfully

2. **Block N+1 through N+∞:** Same process repeats every block
   - Rental is never charged
   - `OwningRental` never accumulates
   - Side chain operates with free resources

**Expected Result:**
`PayRental()` should assert and cause `DonateResourceToken()` to fail, preventing block production until initialization is completed.

**Actual Result:**
`PayRental()` silently returns, `DonateResourceToken()` succeeds, block production continues normally, and side chain permanently evades all rental payments.

**Success Condition:**
Side chain processes transactions indefinitely while `ResourceAmount` dictates non-zero resource consumption, yet no rental tokens are transferred to parent chain consensus contract, verifiable by querying creator balance and consensus contract balance over time.

### Notes

The vulnerability is particularly concerning because:

1. The initialization requirement is documented and expected (as shown in tests), but not enforced at the contract level
2. The automatic nature of `DonateResourceToken()` means the exploit is passive - no active exploitation needed once misconfigured
3. There is no recovery mechanism - once a side chain starts without initialization, there's no way to retroactively collect owed rental fees
4. The silent failure mode provides no visibility into the problem, making detection difficult without off-chain monitoring

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-953)
```csharp
    public override Empty DonateResourceToken(TotalResourceTokensMaps input)
    {
        AssertSenderIsCurrentMiner();
        var donateResourceTokenExecuteHeight = State.DonateResourceTokenExecuteHeight.Value;
        if (donateResourceTokenExecuteHeight == 0)
        {
            donateResourceTokenExecuteHeight = Context.CurrentHeight;
        }

        Assert(donateResourceTokenExecuteHeight == Context.CurrentHeight,
            $"This method already executed in height {State.DonateResourceTokenExecuteHeight.Value}");
        State.DonateResourceTokenExecuteHeight.Value = donateResourceTokenExecuteHeight.Add(1);
        Context.LogDebug(() => $"Start donate resource token. {input}");
        State.LatestTotalResourceTokensMapsHash.Value = HashHelper.ComputeFrom(input);
        Context.LogDebug(() =>
            $"Now LatestTotalResourceTokensMapsHash is {State.LatestTotalResourceTokensMapsHash.Value}");

        var isMainChain = true;
        if (State.DividendPoolContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            if (treasuryContractAddress == null)
            {
                isMainChain = false;
            }
            else
            {
                State.DividendPoolContract.Value = treasuryContractAddress;
            }
        }

        PayResourceTokens(input, isMainChain);

        if (!isMainChain)
        {
            PayRental();
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1021-1022)
```csharp
        var creator = State.SideChainCreator.Value;
        if (creator == null) return;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1040-1096)
```csharp
        foreach (var symbol in Context.Variables.GetStringArray(TokenContractConstants.PayRentalSymbolListName))
        {
            var donates = 0L;

            var availableBalance = GetBalance(creator, symbol);

            // Try to update owning rental.
            var owningRental = State.OwningRental[symbol];
            if (owningRental > 0)
            {
                // If Creator own this symbol and current balance can cover the debt, pay the debt at first.
                if (availableBalance > owningRental)
                {
                    donates = owningRental;
                    // Need to update available balance,
                    // cause existing balance not necessary equals to available balance.
                    availableBalance = availableBalance.Sub(owningRental);
                    State.OwningRental[symbol] = 0;
                }
            }

            var rental = duration.Mul(State.ResourceAmount[symbol]).Mul(State.Rental[symbol]);
            if (availableBalance >= rental) // Success
            {
                donates = donates.Add(rental);
                ModifyBalance(creator, symbol, -donates);
            }
            else // Fail
            {
                // Donate all existing balance. Directly reset the donates.
                donates = GetBalance(creator, symbol);
                State.Balances[creator][symbol] = 0;

                // Update owning rental to record a new debt.
                var own = rental.Sub(availableBalance);
                State.OwningRental[symbol] = State.OwningRental[symbol].Add(own);

                Context.Fire(new RentalAccountBalanceInsufficient
                {
                    Symbol = symbol,
                    Amount = own
                });
            }

            // Side Chain donates.
            var consensusContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
            ModifyBalance(consensusContractAddress, symbol, donates);

            Context.Fire(new RentalCharged()
            {
                Symbol = symbol,
                Amount = donates,
                Payer = creator,
                Receiver = consensusContractAddress
            });
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1129-1142)
```csharp
    private void SetSideChainCreator(Address input)
    {
        Assert(State.SideChainCreator.Value == null, "Creator already set.");
        if (State.ParliamentContract.Value == null)
        {
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
        }

        Assert(Context.Sender == Context.GetZeroSmartContractAddress() ||
               Context.Sender == State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            "No permission.");
        State.SideChainCreator.Value = input;
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/DonateResourceTransactionGenerator.cs (L28-75)
```csharp
    public async Task<List<Transaction>> GenerateTransactionsAsync(Address from, long preBlockHeight,
        Hash preBlockHash)
    {
        var generatedTransactions = new List<Transaction>();

        var chainContext = new ChainContext
        {
            BlockHash = preBlockHash,
            BlockHeight = preBlockHeight
        };

        var tokenContractAddress =
            await _smartContractAddressService.GetAddressByContractNameAsync(chainContext,
                TokenSmartContractAddressNameProvider.StringName);

        if (tokenContractAddress == null) return generatedTransactions;

        var totalResourceTokensMaps = await _totalResourceTokensMapsProvider.GetTotalResourceTokensMapsAsync(
            chainContext);

        ByteString input;
        if (totalResourceTokensMaps != null && totalResourceTokensMaps.BlockHeight == preBlockHeight &&
            totalResourceTokensMaps.BlockHash == preBlockHash)
            // If totalResourceTokensMaps match current block.
            input = totalResourceTokensMaps.ToByteString();
        else
            input = new TotalResourceTokensMaps
            {
                BlockHash = preBlockHash,
                BlockHeight = preBlockHeight
            }.ToByteString();

        generatedTransactions.AddRange(new List<Transaction>
        {
            new()
            {
                From = from,
                MethodName = nameof(TokenContractImplContainer.TokenContractImplStub.DonateResourceToken),
                To = tokenContractAddress,
                RefBlockNumber = preBlockHeight,
                RefBlockPrefix = BlockHelper.GetRefBlockPrefix(preBlockHash),
                Params = input
            }
        });

        Logger.LogTrace("Tx DonateResourceToken generated.");
        return generatedTransactions;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L14-26)
```csharp
    public override Empty InitializeFromParentChain(InitializeFromParentChainInput input)
    {
        Assert(!State.InitializedFromParentChain.Value, "MultiToken has been initialized");
        State.InitializedFromParentChain.Value = true;
        Assert(input.Creator != null, "creator should not be null");
        foreach (var pair in input.ResourceAmount) State.ResourceAmount[pair.Key] = pair.Value;

        foreach (var pair in input.RegisteredOtherTokenContractAddresses)
            State.CrossChainTransferWhiteList[pair.Key] = pair.Value;

        SetSideChainCreator(input.Creator);
        return new Empty();
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenApplicationTests.cs (L1552-1562)
```csharp
        var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        var proposalId = await CreateProposalAsync(TokenContractAddress,
            defaultParliament, nameof(TokenContractStub.InitializeFromParentChain),
            new InitializeFromParentChainInput
            {
                Creator = DefaultAddress,
                ResourceAmount = { { netSymbol, 100 } },
                RegisteredOtherTokenContractAddresses = { { 1, ParliamentContractAddress } }
            });
        await ApproveWithMinersAsync(proposalId);
        await ParliamentContractStub.Release.SendAsync(proposalId);
```
