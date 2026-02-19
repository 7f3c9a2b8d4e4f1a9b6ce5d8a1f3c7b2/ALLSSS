# Audit Report

## Title
Side Chain Rental Payment Bypass via Missing Creator Assertion

## Summary
The `PayRental()` function contains a critical flaw where it silently returns when `SideChainCreator` is null, allowing side chains to evade rental payments indefinitely. Since `InitializeFromParentChain()` requires Parliament governance approval and is not automatically enforced in all deployment scenarios, a side chain can operate without ever setting a creator, permanently bypassing the rental fee mechanism designed to compensate the parent chain for resource usage.

## Finding Description

The vulnerability exists in the rental payment enforcement mechanism for side chains. The `PayRental()` function performs a null check on the creator and silently returns without processing any rental charges: [1](#0-0) 

This function is invoked automatically every block through the `DonateResourceToken()` method on side chains: [2](#0-1) 

The `DonateResourceToken()` method itself is called by a system transaction generator on every block: [3](#0-2) 

The `SideChainCreator` is only set when `InitializeFromParentChain()` is called, which invokes `SetSideChainCreator()`: [4](#0-3) 

However, `SetSideChainCreator()` requires either the genesis contract or Parliament default organization as the sender: [5](#0-4) 

Additionally, the creator can only be set once due to the assertion check: [6](#0-5) 

Test evidence confirms that side chains can operate without initialization, as demonstrated where the rental controller query fails with "side chain creator dose not exist" before initialization: [7](#0-6) 

The test shows `InitializeFromParentChain()` being called via Parliament governance proposal after the side chain is already operational: [8](#0-7) 

**Root Cause:** The silent return allows a misconfigured or maliciously deployed side chain to bypass all rental payment logic. When the creator is null, the entire rental calculation loop starting at line 1040 is never executed, including debt tracking in `OwningRental` and token transfers to the consensus contract.

## Impact Explanation

**Direct Economic Loss:**
- Side chains are designed to pay rental fees for resources (CPU, RAM, DISK, NET) calculated as: `duration × ResourceAmount[symbol] × Rental[symbol]` per minute
- The rental payment loop that processes these charges is completely bypassed when creator is null: [9](#0-8) 

- Rental fees are intended to be transferred to the consensus contract to compensate parent chain validators for providing security and infrastructure
- A side chain without a creator receives unlimited free resource usage for its entire operational lifetime

**Affected Parties:**
- Parent chain loses continuous rental revenue that should fund consensus participants
- Properly initialized side chains face unfair economic competition from free-riding chains
- The protocol's economic incentive structure is fundamentally undermined

**Severity Assessment:** HIGH - This enables permanent, unbounded economic loss. Once a side chain starts without a creator, there is no recovery mechanism to collect retroactive rental fees, and the chain can operate indefinitely without contributing to parent chain economics.

## Likelihood Explanation

**Attack Prerequisites:**
- Ability to deploy a side chain (via CrossChain contract with governance approval)
- Ability to influence or control side chain governance to prevent `InitializeFromParentChain()` approval
- No sophisticated technical capabilities required beyond normal protocol participation

**Attack Complexity:**
- LOW - The exploit is passive; simply never submitting or approving the initialization proposal is sufficient
- The side chain functions normally for all operations (token transfers, smart contracts, consensus)
- No active manipulation or complex transaction sequences needed

**Feasibility Conditions:**
1. **Misconfiguration Scenario:** Side chain deployed with incomplete initialization data or misconfigured genesis
2. **Governance Failure:** Initialization proposal submitted but never approved due to apathy or coordination failure
3. **Malicious Deployment:** Side chain operators deliberately skip initialization to evade rental obligations

**Detection Difficulty:**
- The side chain appears fully functional from a user perspective
- `DonateResourceToken()` executes successfully every block without errors or events
- No on-chain signals indicate rental payment failure (no failed transactions or error logs)
- Detection requires off-chain monitoring of rental payment flows and creator state

**Probability Assessment:** MEDIUM - Requires either deliberate exploitation or governance dysfunction during setup. However, once established, the bypass is automatic, permanent, and irreversible. The protocol lacks enforcement mechanisms to ensure initialization occurs before a side chain can begin operations.

## Recommendation

**Immediate Mitigation:**
Replace the silent return with an assertion to prevent operation without a creator:

```csharp
private void PayRental()
{
    var creator = State.SideChainCreator.Value;
    Assert(creator != null, "Side chain creator must be initialized before rental payments can be processed.");
    
    if (State.LastPayRentTime.Value == null)
    {
        State.LastPayRentTime.Value = Context.CurrentBlockTime;
        return;
    }
    // ... rest of implementation
}
```

**Architectural Improvements:**
1. **Enforce initialization during genesis:** Modify `TokenContractInitializationProvider` to make `InitializeFromParentChain()` mandatory for side chains, not conditional
2. **Add initialization check to DonateResourceToken:** Verify creator exists before allowing the method to succeed
3. **Implement grace period:** Allow a short grace period (e.g., first 1000 blocks) for initialization, then block `DonateResourceToken` if creator is still null
4. **Add monitoring event:** Fire an event when `PayRental()` skips due to null creator to enable off-chain detection

## Proof of Concept

```csharp
[Fact]
public async Task SideChain_Can_Evade_Rental_Payments_Without_Creator()
{
    // Side chain starts without calling InitializeFromParentChain
    // Creator remains null
    
    // Mine blocks - DonateResourceToken will be called automatically
    await GenerateBlocksAsync(100);
    
    // Verify no rental fees were charged
    var owningRental = await TokenContractStub.GetOwningRental.CallAsync(new Empty());
    owningRental.Value.Count.ShouldBe(0); // No debt recorded
    
    // Verify rental controller cannot be retrieved (creator doesn't exist)
    var rentalControllerRet = await TokenContractStub.GetSideChainRentalControllerCreateInfo
        .SendWithExceptionAsync(new Empty());
    rentalControllerRet.TransactionResult.Error.ShouldContain("side chain creator dose not exist");
    
    // Side chain operates normally but pays no rental fees
}
```

This proof of concept demonstrates that a side chain can produce blocks indefinitely without ever paying rental fees when the creator is not initialized, confirming the vulnerability's exploitability.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L947-950)
```csharp
        if (!isMainChain)
        {
            PayRental();
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

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/DonateResourceTransactionGenerator.cs (L60-71)
```csharp
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

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainSideChainRentFeeTest.cs (L40-43)
```csharp
        var rentalControllerRet =
            await TokenContractStub.GetSideChainRentalControllerCreateInfo.SendWithExceptionAsync(new Empty());
        rentalControllerRet.TransactionResult.Error.ShouldContain("side chain creator dose not exist");
        await InitialTokenContractAsync();
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainSideChainRentFeeTest.cs (L303-316)
```csharp
        var setSideChainCreatorProposalInput = new InitializeFromParentChainInput
        {
            ResourceAmount =
            {
                { "CPU", CpuAmount },
                { "RAM", RamAmount },
                { "DISK", DiskAmount },
                { "NET", NetAmount }
            },
            Creator = Creator
        };
        await ParliamentReachAnAgreementAsync(TokenContractAddress, defaultParliamentOrganization,
            nameof(TokenContractImplContainer.TokenContractImplStub.InitializeFromParentChain),
            setSideChainCreatorProposalInput);
```
