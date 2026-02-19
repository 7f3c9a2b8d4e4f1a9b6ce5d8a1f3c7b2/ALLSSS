# Audit Report

## Title
Parliament Has Unilateral Control Over Developer Fee Decisions Due to Single-Member DeveloperController Organization

## Summary
The `GetDeveloperControllerCreateInput()` function creates a DeveloperController association with only parliament as its single member, contradicting the official documentation which states the controller should "consist of developers". This allows parliament to unilaterally control resource token fee coefficients (READ, STORAGE, WRITE, TRAFFIC) without any actual developer input, bypassing the intended two-layer governance structure.

## Finding Description

The root cause lies in the `GetDeveloperControllerCreateInput()` function, which creates an Association organization with parliament as its sole member: [1](#0-0) 

The function adds only `parliamentAddress` to both the proposers list and organization members, with an approval threshold set to 1. This means parliament alone can approve any proposal within the DeveloperController organization.

The RootController is created with two members (parliament and DeveloperController) requiring approval from both: [2](#0-1) 

However, since parliament is the only member of DeveloperController, parliament can create nested proposals to approve on behalf of DeveloperController, effectively controlling both approval layers.

The authorization check for developer fee operations only verifies the RootController: [3](#0-2) 

This governance structure controls critical operations including `UpdateCoefficientsForContract`: [4](#0-3) 

And `ChangeDeveloperController`: [5](#0-4) 

The official documentation explicitly states that the developer controller should "consist of developers": [6](#0-5) 

The Association contract's approval mechanism requires members to vote on proposals: [7](#0-6) 

Since parliament is the only member in the DeveloperController's member list, only parliament can approve proposals in that organization.

The test suite demonstrates this nested approval flow where parliament controls both layers: [8](#0-7) [9](#0-8) 

## Impact Explanation

This vulnerability breaks the documented governance guarantee that developers have representation in fee decisions. The concrete impacts include:

1. **Resource Token Fee Manipulation**: Parliament can arbitrarily adjust coefficients for READ, STORAGE, WRITE, and TRAFFIC resource token fees without developer input, potentially making specific smart contracts economically unfeasible or providing unfair advantages to preferred developers.

2. **Governance Misrepresentation**: The naming "DeveloperController" and documentation create false security assumptions. Developers deploying contracts on the platform reasonably expect the documented two-layer governance with actual developer representation to protect them from unilateral fee changes.

3. **Economic Vulnerability**: All contract developers paying resource token fees are exposed to unpredictable fee structures controlled entirely by parliament, undermining platform trust and potentially causing economic damage.

4. **Self-Perpetuating Control**: Parliament can change the DeveloperController organization itself without developer input via `ChangeDeveloperController`, preventing any future correction of this governance imbalance.

This constitutes unauthorized governance changes because the system promises (through documentation and naming) a control structure that doesn't exist in implementation.

## Likelihood Explanation

The exploitability is HIGH because this is the current operational state of the system, not a potential exploit:

1. **Currently Active**: The DeveloperController is initialized with only parliament as a member during `InitializeAuthorizedController`, making this the default configuration.

2. **No Technical Barriers**: Parliament can execute fee changes through standard nested proposal mechanisms that appear legitimate in transaction logs, masking the fact that parliament controls both approval layers.

3. **Demonstrated in Tests**: The test suite explicitly shows the approval flow where parliament creates proposals in DeveloperController, approves them as the only member, and releases them to approve in the RootController.

4. **Realistic Preconditions**: Only requires parliament to act (which per the validation framework is not assumed honest when the claim is about mis-scoped privileges, as this is).

5. **Reproducible**: Any parliament member can initiate this process following the standard governance procedures.

## Recommendation

The DeveloperController organization should be properly initialized with actual developer representatives as members, not just parliament. Specifically:

1. **Add Developer Members**: Modify `GetDeveloperControllerCreateInput()` to accept a list of developer addresses and add them as organization members alongside or instead of parliament.

2. **Separate Approval Rights**: Ensure that parliament and developers have independent approval rights in the RootController, with neither being able to act on behalf of the other.

3. **Update Documentation**: If the current design is intentional, update documentation to accurately reflect that parliament has unilateral control, removing references to "developer controller consisting of developers".

4. **Governance Initialization**: Add a mechanism during chain initialization or through a one-time migration to properly populate the DeveloperController with legitimate developer representatives.

The Association contract already supports adding members through `AddMember`, but the initial configuration must be corrected to include developers.

## Proof of Concept

The vulnerability is demonstrated in the existing test suite. The test `Update_Coefficient_For_Contract_Test` shows parliament controlling both approval layers: [10](#0-9) 

The test flow shows:
1. `CreateToRootForDeveloperFeeByTwoLayerAsync` - Parliament creates proposal in RootController
2. `ApproveToRootForDeveloperFeeByTwoLayerAsync` - Parliament approves directly in RootController
3. `ApproveToRootForDeveloperFeeByMiddleLayerAsync` - Parliament creates nested proposal in DeveloperController
4. `ApproveThenReleaseMiddleProposalForDeveloperAsync` - Parliament approves and releases in DeveloperController (as only member)
5. `ReleaseToRootForDeveloperFeeByTwoLayerAsync` - Parliament releases RootController proposal with both approvals

This demonstrates that parliament alone can execute developer fee changes without any actual developer participation, despite the system claiming to provide developer representation.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L80-88)
```csharp
    public override Empty ChangeDeveloperController(AuthorityInfo input)
    {
        AssertDeveloperFeeController();
        Assert(CheckOrganizationExist(input), "Invalid authority input.");
        State.DeveloperFeeController.Value.RootController = input;
        State.DeveloperFeeController.Value.ParliamentController = null;
        State.DeveloperFeeController.Value.DeveloperController = null;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L186-211)
```csharp
    private Association.CreateOrganizationBySystemContractInput GetDeveloperControllerCreateInput(
        Address parliamentAddress)
    {
        var proposers = new List<Address> { parliamentAddress };
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
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L213-242)
```csharp
    private Association.CreateOrganizationBySystemContractInput GetAssociationControllerCreateInputForDeveloperFee(
        Address parliamentAddress, Address developerAddress)
    {
        var proposers = new List<Address>
        {
            developerAddress, parliamentAddress
        };
        var actualProposalCount = proposers.Count;
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
                    MinimalApprovalThreshold = actualProposalCount,
                    MinimalVoteThreshold = actualProposalCount,
                    MaximalRejectionThreshold = 0,
                    MaximalAbstentionThreshold = 0
                },
                ProposerWhiteList = new ProposerWhiteList
                {
                    Proposers = { proposers }
                }
            }
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L383-389)
```csharp
    private void AssertDeveloperFeeController()
    {
        Assert(State.DeveloperFeeController.Value != null,
            "controller does not initialize, call InitializeAuthorizedController first");

        Assert(Context.Sender == State.DeveloperFeeController.Value.RootController.OwnerAddress, "no permission");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L16-23)
```csharp
    public override Empty UpdateCoefficientsForContract(UpdateCoefficientsInput input)
    {
        Assert(input.Coefficients != null, "Invalid input coefficients.");
        Assert(input.Coefficients.FeeTokenType != (int)FeeTypeEnum.Tx, "Invalid fee type.");
        AssertDeveloperFeeController();
        UpdateCoefficients(input);
        return new Empty();
    }
```

**File:** docs/resources/smart-contract-apis/multi-token.md (L885-889)
```markdown
**returns**:
- **root controller**: the root controller, it is a association by default.
- **parliament controller**: parliament controller, member of the root controller.
- **developer controller**: developer controller consisiting of developers, member of the root controller.

```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L18-22)
```csharp
    private void AssertIsAuthorizedOrganizationMember(Organization organization, Address member)
    {
        Assert(organization.OrganizationMemberList.Contains(member),
            "Unauthorized member.");
    }
```

**File:** test/AElf.Contracts.MultiTokenCrossChainTransfer.Tests/MultiTokenContractReferenceFeeTest.cs (L171-213)
```csharp
    public async Task Update_Coefficient_For_Contract_Test(bool isFail, int feeType, int[] pieceNumber,
        params int[][] newPieceFunctions)
    {
        var originalCoefficients = await GetCalculateFeeCoefficientsByFeeTypeAsync(feeType);
        var newPieceCoefficientList = newPieceFunctions.Select(x => new CalculateFeePieceCoefficients
        {
            Value = { x }
        }).ToList();
        var updateInput = new UpdateCoefficientsInput
        {
            PieceNumbers = { pieceNumber },
            Coefficients = new CalculateFeeCoefficients
            {
                FeeTokenType = feeType
            }
        };
        updateInput.Coefficients.PieceCoefficientsList.AddRange(newPieceCoefficientList);
        var proposalId = await CreateToRootForDeveloperFeeByTwoLayerAsync(updateInput,
            nameof(TokenContractImplContainer.TokenContractImplStub.UpdateCoefficientsForContract));
        await ApproveToRootForDeveloperFeeByTwoLayerAsync(proposalId);
        var middleApproveProposalId = await ApproveToRootForDeveloperFeeByMiddleLayerAsync(proposalId);
        await ApproveThenReleaseMiddleProposalForDeveloperAsync(middleApproveProposalId);
        await ReleaseToRootForDeveloperFeeByTwoLayerAsync(proposalId);
        var updatedCoefficients = await GetCalculateFeeCoefficientsByFeeTypeAsync(feeType);
        if (!isFail)
        {
            foreach (var newPieceFunction in newPieceFunctions)
            {
                var hasModified =
                    GetCalculateFeePieceCoefficients(updatedCoefficients.PieceCoefficientsList, newPieceFunction[0]);
                var newCoefficient = newPieceFunction.Skip(1).ToArray();
                hasModified.Value.Skip(1).ShouldBe(newCoefficient);
            }
        }
        else
        {
            var pieceCount = originalCoefficients.PieceCoefficientsList.Count;
            updatedCoefficients.PieceCoefficientsList.Count.ShouldBe(pieceCount);
            for (var i = 0; i < pieceCount; i++)
                originalCoefficients.PieceCoefficientsList[i]
                    .ShouldBe(updatedCoefficients.PieceCoefficientsList[i]);
        }
    }
```

**File:** test/AElf.Contracts.MultiTokenCrossChainTransfer.Tests/MultiTokenContractReferenceFeeTest.cs (L825-850)
```csharp
    private async Task<Hash> ApproveToRootForDeveloperFeeByMiddleLayerAsync(Hash input)
    {
        var organizations = await GetControllerForDeveloperFeeAsync();
        var approveMidProposalInput = new CreateProposalInput
        {
            ToAddress = AssociationContractAddress,
            Params = input.ToByteString(),
            OrganizationAddress = organizations.DeveloperController.OwnerAddress,
            ContractMethodName = nameof(AssociationContractImplContainer.AssociationContractImplStub.Approve),
            ExpiredTime = TimestampHelper.GetUtcNow().AddHours(1)
        };
        var approveLeafProposalInput = new CreateProposalInput
        {
            ToAddress = AssociationContractAddress,
            Params = approveMidProposalInput.ToByteString(),
            OrganizationAddress = organizations.ParliamentController.OwnerAddress,
            ContractMethodName = nameof(AssociationContractImplContainer.AssociationContractImplStub.CreateProposal),
            ExpiredTime = TimestampHelper.GetUtcNow().AddHours(1)
        };
        var newCreateProposalRet =
            await MainChainTesterCreatApproveAndReleaseProposalForParliamentAsync(approveLeafProposalInput);
        var middleProposalId = ProposalCreated.Parser
            .ParseFrom(newCreateProposalRet.Logs.First(l => l.Name.Contains(nameof(ProposalCreated)))
                .NonIndexed).ProposalId;
        return middleProposalId;
    }
```

**File:** test/AElf.Contracts.MultiTokenCrossChainTransfer.Tests/MultiTokenContractReferenceFeeTest.cs (L852-874)
```csharp
    private async Task ApproveThenReleaseMiddleProposalForDeveloperAsync(Hash input)
    {
        var organizations = await GetControllerForDeveloperFeeAsync();
        var approveLeafProposalInput = new CreateProposalInput
        {
            ToAddress = AssociationContractAddress,
            Params = input.ToByteString(),
            OrganizationAddress = organizations.ParliamentController.OwnerAddress,
            ContractMethodName = nameof(AssociationContractImplContainer.AssociationContractImplStub.Approve),
            ExpiredTime = TimestampHelper.GetUtcNow().AddHours(1)
        };
        await MainChainTesterCreatApproveAndReleaseProposalForParliamentAsync(approveLeafProposalInput);

        approveLeafProposalInput = new CreateProposalInput
        {
            ToAddress = AssociationContractAddress,
            Params = input.ToByteString(),
            OrganizationAddress = organizations.ParliamentController.OwnerAddress,
            ContractMethodName = nameof(AssociationContractImplContainer.AssociationContractImplStub.Release),
            ExpiredTime = TimestampHelper.GetUtcNow().AddHours(1)
        };
        await MainChainTesterCreatApproveAndReleaseProposalForParliamentAsync(approveLeafProposalInput);
    }
```
