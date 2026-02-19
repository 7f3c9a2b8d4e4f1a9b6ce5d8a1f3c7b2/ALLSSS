### Title
Zero ResourceAmount Validation Allows Side Chains to Bypass Rental Fees

### Summary
The `UpdateRentedResources` method in the MultiToken contract accepts zero values for `ResourceAmount`, which causes the `PayRental` function to charge zero rental fees. This violates the invariant established during side chain creation that requires positive resource amounts, allowing side chains to use resources (CPU, RAM, DISK, NET) without payment to validators.

### Finding Description

The vulnerability exists in the rental calculation and validation logic:

**Rental Calculation Location:** [1](#0-0) 

The rental calculation multiplies `duration * ResourceAmount[symbol] * Rental[symbol]`. When `ResourceAmount[symbol]` is zero, the entire rental becomes zero regardless of duration or rental rate.

**Insufficient Validation:** [2](#0-1) 

The `UpdateRentedResources` method only validates that resource amounts are non-negative (`pair.Value >= 0`), explicitly allowing zero values. This contradicts the stricter validation enforced during initial side chain creation.

**Inconsistent Initial Validation:** [3](#0-2) 

During side chain creation, the system requires `resourceTokenMap[resourceTokenSymbol] > 0`, establishing the invariant that resource amounts must be positive. The `UpdateRentedResources` validation violates this invariant by accepting zero.

**Authorization Control:** [4](#0-3) 

The method is protected by `AssertControllerForSideChainRental`, which requires approval from both Parliament and the SideChainCreator through an Association multi-sig organization.

### Impact Explanation

**Direct Financial Loss:**
When `ResourceAmount` is set to zero for any resource token (CPU, RAM, DISK, NET), the side chain pays no rental fees for that resource. The `PayRental` function transfers fees to the consensus contract address (validators), so this directly reduces validator revenue.

**Quantified Impact:**
Based on test constants, a side chain using 4 CPU cores, 8 GiB RAM, 512 GiB disk, and 1000 MB network at 100 tokens per unit per minute would pay zero instead of `(4*100 + 8*100 + 512*100 + 1000*100) = 152,400 tokens per minute`. [5](#0-4) 

**Who Is Affected:**
Validators lose rental revenue they should receive through the consensus contract. The main chain's economic security model is undermined as side chains can operate without contributing to validator incentives.

**Severity Justification:**
High severity due to complete bypass of the rental fee mechanism, though reduced by governance requirements. The code defect makes exploitation possible where it should be impossible.

### Likelihood Explanation

**Attacker Capabilities:**
Requires both the side chain creator and Parliament to approve the change through the Association controller organization. [6](#0-5) 

The controller requires unanimous approval from both members (minimalApprovalThreshold = 2, minimalVoteThreshold = 2).

**Attack Complexity:**
Low technical complexity once governance approval is obtained. The execution is straightforward:
1. Create proposal to call `UpdateRentedResources` with zero ResourceAmount
2. Obtain Parliament approval
3. Obtain SideChainCreator approval  
4. Release proposal

**Feasibility Conditions:**
- Side chain creator has direct financial incentive (cost reduction to zero)
- Parliament theoretically opposes (protects validator revenue)
- However, Parliament could be compromised, err, or face political pressure
- The code validation failure means governance is the ONLY protection

**Detection Constraints:**
The change is transparent on-chain and immediately detectable. It can be reversed through the same governance process. However, rental revenue loss occurs continuously until reversed.

**Probability Reasoning:**
Medium-to-low probability in normal operation due to Parliament's anti-incentive. However, the code defect is certain - the validation objectively allows zero when it should not. The inconsistency with creation-time validation (`> 0` vs `>= 0`) indicates a bug rather than intentional design.

### Recommendation

**Code-Level Mitigation:**
Modify the validation in `UpdateRentedResources` to match the creation-time requirement:

```csharp
Assert(pair.Value > 0, "Invalid amount.");  // Change from >= 0 to > 0
``` [7](#0-6) 

**Invariant Enforcement:**
Ensure consistent validation across all paths that set `ResourceAmount`. The same positive-value requirement that applies during `AssertValidResourceTokenAmount` should apply to `UpdateRentedResources`. [8](#0-7) 

**Test Cases:**
Add negative test case verifying that `UpdateRentedResources` with zero values fails with appropriate error message. Update existing test to confirm non-zero requirement. [9](#0-8) 

### Proof of Concept

**Required Initial State:**
1. Side chain created with positive ResourceAmount (e.g., CPU: 4, RAM: 8, DISK: 512, NET: 1000)
2. SideChainRentalController initialized with Parliament + SideChainCreator as members
3. Rental rates configured (e.g., 100 tokens per unit per minute)

**Transaction Steps:**
1. Create Association proposal calling `UpdateRentedResources` with:
   ```
   ResourceAmount: { "CPU": 0, "RAM": 0, "DISK": 0, "NET": 0 }
   ```
2. Parliament approves proposal (requires miners' approval)
3. SideChainCreator approves proposal
4. Release proposal to execute `UpdateRentedResources`
5. Wait for next `DonateResourceToken` call (triggers `PayRental`)

**Expected vs Actual Result:**
- Expected: Transaction at step 4 should fail with "Invalid amount" error
- Actual: Transaction succeeds, setting all ResourceAmount values to zero

**Success Condition:**
After exploitation, `GetResourceUsage` returns zero for all resources, and subsequent `PayRental` calls charge zero fees despite continued resource usage. The `RentalCharged` events show amount = 0. [10](#0-9) 

### Notes

The vulnerability stems from validation inconsistency rather than missing authorization. While governance provides a layer of defense, the code should enforce the business logic invariant that resource amounts must be positive. The fact that initial creation requires `> 0` but updates allow `>= 0` indicates a coding error rather than intentional flexibility.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1061-1061)
```csharp
            var rental = duration.Mul(State.ResourceAmount[symbol]).Mul(State.Rental[symbol]);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1089-1095)
```csharp
            Context.Fire(new RentalCharged()
            {
                Symbol = symbol,
                Amount = donates,
                Payer = creator,
                Receiver = consensusContractAddress
            });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1114-1127)
```csharp
    public override Empty UpdateRentedResources(UpdateRentedResourcesInput input)
    {
        AssertControllerForSideChainRental();
        foreach (var pair in input.ResourceAmount)
        {
            Assert(
                Context.Variables.GetStringArray(TokenContractConstants.PayRentalSymbolListName).Contains(pair.Key),
                "Invalid symbol.");
            Assert(pair.Value >= 0, "Invalid amount.");
            State.ResourceAmount[pair.Key] = pair.Value;
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L139-145)
```csharp
    private void AssertValidResourceTokenAmount(SideChainCreationRequest sideChainCreationRequest)
    {
        var resourceTokenMap = sideChainCreationRequest.InitialResourceAmount;
        foreach (var resourceTokenSymbol in Context.Variables.GetStringArray(PayRentalSymbolListName))
            Assert(resourceTokenMap.ContainsKey(resourceTokenSymbol) && resourceTokenMap[resourceTokenSymbol] > 0,
                "Invalid side chain resource token request.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L244-268)
```csharp
    private Association.CreateOrganizationBySystemContractInput GetControllerCreateInputForSideChainRental(
        Address sideChainCreator, Address parliamentAddress)
    {
        var proposers = new List<Address> { parliamentAddress, sideChainCreator };
        return new Association.CreateOrganizationBySystemContractInput
        {
            OrganizationCreationInput = new Association.CreateOrganizationInput
            {
                OrganizationMemberList = new OrganizationMemberList
                {
                    OrganizationMembers = { proposers }
                },
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = proposers.Count,
                    MinimalVoteThreshold = proposers.Count,
                    MaximalRejectionThreshold = 0,
                    MaximalAbstentionThreshold = 0
                },
                ProposerWhiteList = new ProposerWhiteList
                {
                    Proposers = { proposers }
                }
            }
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L407-413)
```csharp
    private void AssertControllerForSideChainRental()
    {
        Assert(State.SideChainRentalController.Value != null,
            "controller does not initialize, call InitializeAuthorizedController first");
        // ReSharper disable once PossibleNullReferenceException
        Assert(State.SideChainRentalController.Value.OwnerAddress == Context.Sender, "no permission");
    }
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainSideChainRentFeeTest.cs (L19-26)
```csharp
    private const int CpuAmount = 4;
    private const int RamAmount = 8;
    private const int DiskAmount = 512;
    private const int NetAmount = 1000;

    private const long ResourceSupply = 1_0000_0000_00000000;

    private const long Rental = 100;
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainSideChainRentFeeTest.cs (L262-281)
```csharp
        var updateParam = new UpdateRentedResourcesInput();
        var symbolDic = new Dictionary<string, int> { ["CPU"] = 101 };
        updateParam.ResourceAmount.Add(symbolDic);
        var updateProposal = new CreateProposalInput
        {
            ToAddress = TokenContractAddress,
            ContractMethodName = nameof(TokenContractImplContainer.TokenContractImplStub.UpdateRentedResources),
            Params = updateParam.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = newControllerAddress
        };
        var updateProposalRet = (await AssociationContractStub.CreateProposal.SendAsync(updateProposal))
            .TransactionResult;
        var updateProposalId = new Hash();
        updateProposalId.MergeFrom(updateProposalRet.ReturnValue);
        await AssociationContractStub.Approve.SendAsync(updateProposalId);
        await AssociationContractStub.Release.SendAsync(updateProposalId);
        var resourceUsage = await TokenContractStub.GetResourceUsage.CallAsync(new Empty());
        resourceUsage.Value["CPU"].ShouldBe(101);
    }
```
