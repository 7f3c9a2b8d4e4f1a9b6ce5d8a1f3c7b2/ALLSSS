### Title
Non-Burnable Token Fee Accumulation via Unvalidated User Contract Method Fee Configuration

### Summary
User contract method fees configured through `Configuration.SetConfiguration` bypass the `IsBurnable` validation that is enforced for system contract fees. When non-burnable tokens are used as transaction fees, the `TransferTransactionFeesToFeeReceiver` function returns early without burning or distributing these fees, causing them to accumulate indefinitely in the MultiToken contract's balance.

### Finding Description

**Root Cause:** The Configuration contract's `SetConfiguration` method lacks token burnability validation when setting user contract method fees. [1](#0-0) 

This contrasts with system contract method fee configuration, which validates `IsBurnable`: [2](#0-1) [3](#0-2) 

**Execution Path:**
1. Governance sets user contract method fees via `Configuration.SetConfiguration` with a non-burnable token
2. User contract calls are charged in the non-burnable token via `ChargeUserContractTransactionFees` [4](#0-3) 

3. Fees are retrieved from Configuration without validation: [5](#0-4) 

4. Miners claim fees, adding them to MultiToken contract balance: [6](#0-5) 

5. `TransferTransactionFeesToFeeReceiver` returns early for non-burnable tokens, skipping distribution: [7](#0-6) 

**Why Protections Fail:** The `SetConfiguration` method only checks authorization but not token properties, unlike `SetMethodFee` in system contracts which enforces the `IsBurnable` requirement.

### Impact Explanation

**Direct Fund Impact:**
- Non-burnable token fees accumulate in the MultiToken contract (at `Context.Self` address) without being burned or distributed to the treasury/dividend pool
- These accumulated fees become permanently locked, as there is no recovery mechanism for extracting them
- On main chains: Fees that should be donated to the dividend pool are trapped
- On side chains: Fees that should be transferred to the FeeReceiver or burned are trapped

**Affected Parties:**
- Protocol treasury/dividend pool loses fee revenue that should be distributed to stakers
- Side chain fee receivers lose their designated fee share
- Token holders expecting fee burning for deflationary pressure receive none

**Quantification:** For every transaction using a non-burnable token as a user contract method fee, 100% of the fee amount accumulates in the contract. With high-volume user contracts, this could represent significant value locked permanently.

### Likelihood Explanation

**Attacker Capabilities:** 
Requires governance authorization through the Configuration contract's controller (Parliament contract's default organization by default). This means miners/governance participants must approve the configuration change. [8](#0-7) 

**Attack Complexity:** Low - a single governance proposal can configure non-burnable token fees: [9](#0-8) 

**Feasibility:** 
- Governance error: Accidental configuration of non-burnable tokens as fees
- Malicious governance: Intentional misdirection of fee revenue
- Tests only cover burnable tokens, missing this edge case: [10](#0-9) 

**Economic Rationality:** No cost to governance beyond proposal creation. Exploitable through governance oversight or compromise.

### Recommendation

**Code-Level Mitigation:**

Add `IsBurnable` validation to `Configuration.SetConfiguration` when the key indicates user contract method fees:

```csharp
public override Empty SetConfiguration(SetConfigurationInput input)
{
    AssertPerformedByConfigurationControllerOrZeroContract();
    Assert(input.Key.Any() && input.Value != ByteString.Empty, "Invalid set config input.");
    
    // Add validation for user contract method fees
    if (input.Key.StartsWith("UserContractMethodFee"))
    {
        var methodFees = new UserContractMethodFees();
        methodFees.MergeFrom(input.Value);
        foreach (var fee in methodFees.Fees)
        {
            Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(
                new StringValue { Value = fee.Symbol }).Value,
                $"Token {fee.Symbol} cannot set as method fee.");
        }
    }
    
    State.Configurations[input.Key] = new BytesValue { Value = input.Value };
    Context.Fire(new ConfigurationSet { Key = input.Key, Value = input.Value });
    return new Empty();
}
```

**Alternative Fix:** Modify `TransferTransactionFeesToFeeReceiver` to handle non-burnable tokens by transferring them instead of returning early, but this violates the design principle that fee tokens must be burnable.

**Test Cases:**
1. Attempt to set non-burnable token as user contract method fee → should fail
2. Verify existing burnable token configurations continue to work
3. Test fee accumulation doesn't occur for any token type

### Proof of Concept

**Initial State:**
1. Create a non-burnable token "NBT"
2. Create a user contract with a method "TestMethod"
3. Mint NBT tokens to a test user

**Transaction Steps:**
1. Governance creates proposal to set user contract method fee:
   - Key: "UserContractMethodFee"
   - Value: `{Fees: [{Symbol: "NBT", BasicFee: 1000}]}`
2. Governance approves and releases proposal
3. Configuration is set successfully (no validation failure)
4. Test user calls user contract's TestMethod
5. User is charged 1000 NBT (plus size fee in ELF)
6. Miner calls `ClaimTransactionFees` at next block
7. 1000 NBT is added to MultiToken contract balance
8. `TransferTransactionFeesToFeeReceiver` returns early due to `!IsBurnable` check
9. 1000 NBT remains in MultiToken contract balance

**Expected Result:** Configuration should fail at step 2 with "Token NBT cannot set as method fee"

**Actual Result:** 1000 NBT accumulates in MultiToken contract without being burned or distributed, permanently locked.

**Success Condition:** Query MultiToken contract balance for NBT after multiple transactions shows increasing accumulation with no corresponding burn/transfer events.

### Notes

The vulnerability specifically affects **user contract method fees** configured via the Configuration contract. System contract method fees and transaction size fee tokens are properly validated and cannot use non-burnable tokens. The `IsBurnable` property is immutable after token creation, so tokens cannot change from burnable to non-burnable post-configuration.

### Citations

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract.cs (L10-21)
```csharp
    public override Empty SetConfiguration(SetConfigurationInput input)
    {
        AssertPerformedByConfigurationControllerOrZeroContract();
        Assert(input.Key.Any() && input.Value != ByteString.Empty, "Invalid set config input.");
        State.Configurations[input.Key] = new BytesValue { Value = input.Value };
        Context.Fire(new ConfigurationSet
        {
            Key = input.Key,
            Value = input.Value
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L123-132)
```csharp
    private void AssertValidFeeToken(string symbol, long amount)
    {
        AssertValidSymbolAndAmount(symbol, amount);
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null)
        {
            throw new AssertionException("Token is not found");
        }
        Assert(tokenInfo.IsBurnable, $"Token {symbol} cannot set as method fee.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L252-257)
```csharp
    private bool IsTokenAvailableForMethodFee(string symbol)
    {
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null) throw new AssertionException("Token is not found.");
        return tokenInfo.IsBurnable;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L55-82)
```csharp
    public override ChargeTransactionFeesOutput ChargeUserContractTransactionFees(ChargeTransactionFeesInput input)
    {
        AssertPermissionAndInput(input);
        // Primary token not created yet.
        if (State.ChainPrimaryTokenSymbol.Value == null)
        {
            return new ChargeTransactionFeesOutput { Success = true };
        }

        // Record tx fee bill during current charging process.
        var bill = new TransactionFeeBill();
        var allowanceBill = new TransactionFreeFeeAllowanceBill();
        var fromAddress = Context.Sender;
        var fee = new Dictionary<string, long>();
        var userContractMethodFees = GetActualFee(input.ContractAddress, input.MethodName);
        var isSizeFeeFree = false;
        if (userContractMethodFees != null)
        {
            isSizeFeeFree = userContractMethodFees.IsSizeFeeFree;
        }

        if (userContractMethodFees != null && userContractMethodFees.Fees.Any())
        {
            fee = GetUserContractFeeDictionary(userContractMethodFees);
        }

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L134-165)
```csharp
    private UserContractMethodFees GetActualFee(Address contractAddress, string methodName)
    {
        if (State.ConfigurationContract.Value == null)
            State.ConfigurationContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
        //Get the fee of the specified contract method set by the configuration contract.
        //configuration_key:UserContractMethod_contractAddress_methodName
        var spec = State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = $"{TokenContractConstants.UserContractMethodFeeKey}_{contractAddress.ToBase58()}_{methodName}"
        });
        var fee = new UserContractMethodFees();
        if (!spec.Value.IsNullOrEmpty())
        {
            fee.MergeFrom(spec.Value);
            return fee;
        }

        //If special key is null,get the normal fee set by the configuration contract.
        //configuration_key:UserContractMethod
        var value = State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = TokenContractConstants.UserContractMethodFeeKey
        });
        if (value.Value.IsNullOrEmpty())
        {
            return new UserContractMethodFees();
        }

        fee.MergeFrom(value.Value);
        return fee;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L867-895)
```csharp
    public override Empty ClaimTransactionFees(TotalTransactionFeesMap input)
    {
        AssertSenderIsCurrentMiner();
        var claimTransactionExecuteHeight = State.ClaimTransactionFeeExecuteHeight.Value;

        Assert(claimTransactionExecuteHeight < Context.CurrentHeight,
            $"This method already executed in height {State.ClaimTransactionFeeExecuteHeight.Value}");
        State.ClaimTransactionFeeExecuteHeight.Value = Context.CurrentHeight;
        Context.LogDebug(() => $"Claim transaction fee. {input}");
        State.LatestTotalTransactionFeesMapHash.Value = HashHelper.ComputeFrom(input);
        foreach (var bill in input.Value)
        {
            var symbol = bill.Key;
            var amount = bill.Value;
            ModifyBalance(Context.Self, symbol, amount);
            Context.Fire(new TransactionFeeClaimed
            {
                Symbol = symbol,
                Amount = amount,
                Receiver = Context.Self
            });
            
            TransferTransactionFeesToFeeReceiver(symbol, amount);
        }

        Context.LogDebug(() => "Finish claim transaction fee.");

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1150-1210)
```csharp
    private void TransferTransactionFeesToFeeReceiver(string symbol, long totalAmount)
    {
        Context.LogDebug(() => "Transfer transaction fee to receiver.");

        if (totalAmount <= 0) return;

        var tokenInfo = GetTokenInfo(symbol);
        if (!tokenInfo.IsBurnable)
        {
            return;
        }

        var burnAmount = totalAmount.Div(10);
        if (burnAmount > 0)
            Context.SendInline(Context.Self, nameof(Burn), new BurnInput
            {
                Symbol = symbol,
                Amount = burnAmount
            });

        var transferAmount = totalAmount.Sub(burnAmount);
        if (transferAmount == 0)
            return;
        var treasuryContractAddress =
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
        var isMainChain = treasuryContractAddress != null;
        if (isMainChain)
        {
            // Main chain would donate tx fees to dividend pool.
            if (State.DividendPoolContract.Value == null)
                State.DividendPoolContract.Value = treasuryContractAddress;
            State.Allowances[Context.Self][State.DividendPoolContract.Value][symbol] =
                State.Allowances[Context.Self][State.DividendPoolContract.Value][symbol].Add(transferAmount);
            State.DividendPoolContract.Donate.Send(new DonateInput
            {
                Symbol = symbol,
                Amount = transferAmount
            });
        }
        else
        {
            if (State.FeeReceiver.Value != null)
            {
                Context.SendInline(Context.Self, nameof(Transfer), new TransferInput
                {
                    To = State.FeeReceiver.Value,
                    Symbol = symbol,
                    Amount = transferAmount,
                });
            }
            else
            {
                // Burn all!
                Context.SendInline(Context.Self, nameof(Burn), new BurnInput
                {
                    Symbol = symbol,
                    Amount = transferAmount
                });
            }
        }
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L32-43)
```csharp
    private void AssertPerformedByConfigurationControllerOrZeroContract()
    {
        if (State.ConfigurationController.Value == null)
        {
            var defaultConfigurationController = GetDefaultConfigurationController();
            State.ConfigurationController.Value = defaultConfigurationController;
        }

        Assert(
            State.ConfigurationController.Value.OwnerAddress == Context.Sender ||
            Context.GetZeroSmartContractAddress() == Context.Sender, "No permission.");
    }
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutionPluginForUserContractMethodFeeTest.cs (L182-188)
```csharp
        var createProposalInput = new SetConfigurationInput
        {
            Key = ConfigurationKey,
            Value = transactionFee.ToByteString()
        };

        await ConfigurationStub.SetConfiguration.SendAsync(createProposalInput);
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutionPluginForUserContractMethodFeeTest.cs (L324-333)
```csharp
        await TokenContractStub.Create.SendAsync(new CreateInput
        {
            Symbol = symbol,
            Decimals = 2,
            IsBurnable = true,
            TokenName = "test token",
            TotalSupply = 1_000_000_00000000L,
            Issuer = DefaultAddress,
            Owner = DefaultAddress,
        });
```
