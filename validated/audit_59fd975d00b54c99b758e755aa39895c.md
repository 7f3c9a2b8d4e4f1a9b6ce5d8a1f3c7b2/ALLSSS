# Audit Report

## Title
Genesis Contract Methods Execute With Only Size Fees When Base Fees Not Configured

## Summary
The Genesis contract's `GetMethodFee()` implementation differs from other system contracts by returning null for unconfigured methods instead of default base fees. This causes the token contract's fee charging logic to skip base fee collection entirely, charging only minimal transaction size fees for expensive contract deployment operations like `ProposeNewContract` and `DeployUserSmartContract`. This enables spam attacks that create state bloat and exhaust network resources at drastically reduced cost.

## Finding Description

The Genesis contract implements a non-standard fee handling pattern. When `GetMethodFee()` is called for methods without configured fees in `State.TransactionFees`, it returns null directly: [1](#0-0) 

This contrasts with other system contracts like VoteContract and ProfitContract, which return default base fees (1-10 ELF) when fees are unconfigured: [2](#0-1) [3](#0-2) 

When the token contract's `ChargeTransactionFees` receives a null `MethodFees` response, it initializes an empty fee dictionary: [4](#0-3) 

The fee charging logic then skips base fee collection when the dictionary is empty: [5](#0-4) 

This means expensive operations execute with only transaction size fees. The affected methods include `ProposeNewContract` (which validates code, computes hashes, stores state, and creates governance proposals) and `DeployUserSmartContract` (which performs code checks, generates proposals, and stores contract metadata).

These methods are publicly accessible. On mainchain, `DeployUserSmartContract` only requires that the transaction is not an inline call: [6](#0-5) [7](#0-6) 

And `ProposeNewContract` has no authorization check beyond validating the contract doesn't already exist: [8](#0-7) 

## Impact Explanation

**Resource Exhaustion**: Attackers can spam contract deployment proposals by repeatedly calling these methods, paying only minimal transaction size fees instead of appropriate base fees. Each call involves SHA256 hash computation, state writes to `ContractProposingInputMap`, cross-contract calls to Parliament for proposal creation, and event generation.

**State Bloat**: Each proposal permanently consumes blockchain state storage in both the Genesis contract's `ContractProposingInputMap` and the Parliament contract's proposal storage. Without adequate fee barriers, attackers can create thousands of proposals cheaply, causing permanent state bloat.

**Network DoS**: Block producers must execute these computationally expensive operations during transaction processing. Mass proposal creation can slow block production and validation, degrading overall network performance for all participants.

**Economic Impact**: The disparity between actual computational cost and fees paid represents a market inefficiency. Transaction size fees are orders of magnitude smaller than appropriate base fees for contract deployment operations, making this attack economically favorable.

## Likelihood Explanation

**Attack Complexity**: LOW - Exploitation requires only repeated calls to public methods with valid contract code. No special permissions or complex setup needed.

**Preconditions**: The vulnerability manifests when Parliament governance has not explicitly configured fees for expensive Genesis contract methods via `SetMethodFee`. While tests demonstrate fees can be configured: [9](#0-8) 

There is no evidence of default fee initialization during chain bootstrap, and the Genesis contract lacks the default fee pattern seen in other contracts.

**Economic Rationality**: HIGHLY FAVORABLE for attackers. Transaction size fees are typically minimal compared to what should be charged for contract deployment operations. An attacker could generate hundreds of spam proposals for the cost of a single legitimate deployment with proper fees.

**Exploitability Window**: PERSISTENT - Until governance explicitly configures fees for all expensive Genesis contract methods, this vulnerability remains exploitable. Given the need for explicit Parliament proposals to set each method's fee, extended periods may exist where methods lack proper configuration.

## Recommendation

Implement default base fees in the Genesis contract's `GetMethodFee()` method similar to other system contracts:

```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    var fees = State.TransactionFees[input.Value];
    if (fees != null) return fees;
    
    if (input.Value == nameof(ReleaseApprovedUserSmartContract))
    {
        return new MethodFees
        {
            MethodName = input.Value,
            IsSizeFeeFree = true
        };
    }
    
    // Add default fees for expensive operations
    switch (input.Value)
    {
        case nameof(ProposeNewContract):
        case nameof(DeployUserSmartContract):
        case nameof(ProposeUpdateContract):
        case nameof(UpdateUserSmartContract):
            return new MethodFees
            {
                Fees =
                {
                    new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                }
            };
        default:
            return new MethodFees
            {
                Fees =
                {
                    new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 1_00000000 }
                }
            };
    }
}
```

Additionally, during chain initialization, explicitly configure fees for critical Genesis contract methods through governance proposals to ensure consistent fee enforcement from chain launch.

## Proof of Concept

```csharp
[Fact]
public async Task Genesis_UnconfiguredFee_OnlyChargesSizeFee_Test()
{
    // Verify ProposeNewContract has no configured fees
    var methodFee = await BasicContractZeroStub.GetMethodFee.CallAsync(new StringValue
    {
        Value = nameof(BasicContractZeroStub.ProposeNewContract)
    });
    
    // Should be null or empty (no default fees unlike other contracts)
    Assert.True(methodFee == null || methodFee.Fees.Count == 0);
    
    // Get initial balance
    var initialBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultSender,
        Symbol = "ELF"
    });
    
    // Call ProposeNewContract with spam contract
    var code = ByteString.CopyFrom(new byte[1024]); // Minimal valid code
    var result = await BasicContractZeroStub.ProposeNewContract.SendAsync(new ContractDeploymentInput
    {
        Category = 0,
        Code = code
    });
    
    // Verify transaction succeeded
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Check final balance - should only deduct size fee (minimal)
    var finalBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultSender,
        Symbol = "ELF"
    });
    
    var feeCharged = initialBalance.Balance - finalBalance.Balance;
    
    // Fee should be minimal (only size fee), much less than 1 ELF base fee
    Assert.True(feeCharged < 1_00000000); // Less than 1 ELF
    
    // Verify proposal was created (state bloat occurred)
    var proposalHash = result.Output;
    Assert.NotNull(proposalHash);
}
```

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L34-46)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var fees = State.TransactionFees[input.Value];
        if (fees == null && input.Value == nameof(ReleaseApprovedUserSmartContract))
        {
            fees = new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
        }

        return fees;
```

**File:** contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs (L35-58)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var tokenAmounts = State.TransactionFees[input.Value];
        if (tokenAmounts != null) return tokenAmounts;

        switch (input.Value)
        {
            case nameof(Register):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
            default:
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 1_00000000 }
                    }
                };
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L35-58)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var methodFees = State.TransactionFees[input.Value];
        if (methodFees != null) return methodFees;

        switch (input.Value)
        {
            case nameof(CreateScheme):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
            default:
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 1_00000000 }
                    }
                };
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-52)
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

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L273-299)
```csharp
        var successToChargeBaseFee = true;

        SetOrRefreshTransactionFeeFreeAllowances(fromAddress);
        var freeAllowancesMap = CalculateTransactionFeeFreeAllowances(fromAddress);

        if (fee.Count != 0)
        {
            // If base fee is set before, charge base fee.
            successToChargeBaseFee =
                ChargeBaseFee(fee, fromAddress, ref bill, freeAllowancesMap, ref allowanceBill, delegations);
        }

        //For delegation, if the base fee fails to be charged, the size fee will not be charged
        if (delegations != null && !successToChargeBaseFee)
        {
            return false;
        }

        var successToChargeSizeFee = true;
        if (!isSizeFeeFree)
        {
            // If IsSizeFeeFree == true, do not charge size fee.
            successToChargeSizeFee =
                ChargeSizeFee(input, fromAddress, ref bill, freeAllowancesMap, ref allowanceBill, delegations);
        }

        return successToChargeBaseFee && successToChargeSizeFee;
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L344-357)
```csharp
    private void AssertUserDeployContract()
    {
        // Only the symbol of main chain or public side chain is native symbol.
        RequireTokenContractContractAddressSet();
        var primaryTokenSymbol = State.TokenContract.GetPrimaryTokenSymbol.Call(new Empty()).Value;
        if (Context.Variables.NativeSymbol == primaryTokenSymbol)
        {
            return;
        }

        RequireParliamentContractAddressSet();
        var whitelist = State.ParliamentContract.GetProposerWhiteList.Call(new Empty());
        Assert(whitelist.Proposers.Contains(Context.Sender), "No permission.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L384-388)
```csharp
    private void AssertInlineDeployOrUpdateUserContract()
    {
        Assert(Context.Origin == Context.Sender || !IsMainChain(),
            "Deploy or update contracts using inline transactions is not allowed.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L122-173)
```csharp
    public override Hash ProposeNewContract(ContractDeploymentInput input)
    {
        // AssertDeploymentProposerAuthority(Context.Sender);
        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        AssertContractNotExists(codeHash);
        var proposedContractInputHash = CalculateHashFromInput(input);
        RegisterContractProposingData(proposedContractInputHash);

        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();

        if (input.ContractOperation != null)
        {
            ValidateContractOperation(input.ContractOperation, 0, codeHash);
            
            // Remove one time signer if exists. Signer is only needed for validating signature.
            RemoveOneTimeSigner(input.ContractOperation.Deployer);
            
            AssertContractAddressAvailable(input.ContractOperation.Deployer, input.ContractOperation.Salt);
        }

        // Create proposal for deployment
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput = new CreateProposalInput
            {
                ToAddress = Context.Self,
                ContractMethodName =
                    nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.ProposeContractCodeCheck),
                Params = new ContractCodeCheckInput
                {
                    ContractInput = input.ToByteString(),
                    CodeCheckReleaseMethod = nameof(DeploySmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = input.Category,
                    IsSystemContract = false
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput.ToByteString());

        Context.Fire(new ContractProposed
        {
            ProposedContractInputHash = proposedContractInputHash
        });

        return proposedContractInputHash;
    }
```

**File:** test/AElf.Contracts.EconomicSystem.Tests/BVT/TransactionFeeProviderTests.cs (L110-122)
```csharp
    public async Task Genesis_FeeProvider_Test()
    {
        await ExecuteProposalForParliamentTransaction(ContractZeroAddress, MethodName, new MethodFees
        {
            MethodName = nameof(BasicContractZeroStub.DeploySmartContract),
            Fees = { TokenAmount }
        });
        var result = await BasicContractZeroStub.GetMethodFee.CallAsync(new StringValue
        {
            Value = nameof(BasicContractZeroStub.DeploySmartContract)
        });
        result.Fees.First().ShouldBe(TokenAmount);
    }
```
