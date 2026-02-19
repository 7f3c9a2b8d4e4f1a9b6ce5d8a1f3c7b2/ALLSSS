### Title
Governance Degradation via Unvalidated DeveloperFeeController Change Allows Trivial Organization Bypass

### Summary
The `AssertDeveloperFeeController()` function only validates sender authorization against the RootController's owner address but does not verify the RootController organization itself maintains appropriate governance thresholds. This allows the current RootController to replace itself with a trivial single-member organization (MinimalApprovalThreshold = 1), permanently degrading multi-signature governance to unilateral control over critical resource token fee coefficients.

### Finding Description

The vulnerability exists in the interaction between `AssertDeveloperFeeController()` and `ChangeDeveloperController()`: [1](#0-0) 

This assertion function only checks that the sender matches the RootController's OwnerAddress but performs no validation of the RootController organization's governance structure (member count, approval thresholds, etc.).

The `ChangeDeveloperController()` function allows changing the RootController: [2](#0-1) 

The only validation performed is `CheckOrganizationExist(input)`, which merely verifies the organization exists: [3](#0-2) 

The Association contract's validation logic permits single-member organizations with minimal thresholds: [4](#0-3) 

This validation only requires `MinimalApprovalThreshold > 0`, allowing a trivial 1-of-1 organization.

The initial DeveloperFeeController is intentionally designed as a 2-of-2 multisig requiring both Parliament and Developer approval: [5](#0-4) 

However, this secure initial configuration can be degraded to a 1-of-1 organization through `ChangeDeveloperController()` with no prevention mechanism.

### Impact Explanation

Control over the DeveloperFeeController grants authority to call `UpdateCoefficientsForContract()`: [6](#0-5) 

This function controls fee calculation coefficients for critical resource tokens (READ, WRITE, STORAGE, TRAFFIC). An attacker with unilateral control could:

1. **Economic Manipulation**: Set coefficients to 0, making resource usage free and breaking fee economics
2. **Network DoS**: Set coefficients to extreme values, making transactions prohibitively expensive
3. **Protocol Integrity**: Permanently degrade governance from secure 2-of-2 multisig to insecure 1-of-1 control

The impact violates the stated invariant: "Organization thresholds...method-fee provider authority" must be maintained at all times. Once governance is degraded, the compromise is permanent and irreversible without external intervention.

### Likelihood Explanation

The attack requires:

1. **Initial Compromise**: Attacker must convince or compromise the current RootController (2-of-2 multisig) to approve a proposal calling `ChangeDeveloperController()`
2. **Organization Creation**: Create a trivial Association organization with 1 member and MinimalApprovalThreshold = 1 (passes all validation)
3. **Governance Degradation**: Once the change executes, attacker has permanent unilateral control

While initial compromise is difficult (requires 2-of-2 approval), the vulnerability enables:
- Social engineering attacks (seemingly innocent governance "simplification")
- Persistent backdoor if either governance member is temporarily compromised
- No detection mechanism for governance quality degradation
- No recovery mechanism once degraded

The likelihood is moderate because the initial compromise requirement is offset by the permanent nature of the degradation and the complete lack of protective controls against weak governance configurations.

### Recommendation

Add minimum governance threshold validation to `ChangeDeveloperController()` and similar controller change functions:

```csharp
public override Empty ChangeDeveloperController(AuthorityInfo input)
{
    AssertDeveloperFeeController();
    Assert(CheckOrganizationExist(input), "Invalid authority input.");
    
    // NEW: Validate minimum governance standards
    var organization = State.AssociationContract.GetOrganization.Call(input.OwnerAddress);
    Assert(organization.OrganizationMemberList.OrganizationMembers.Count >= 2, 
        "Organization must have at least 2 members.");
    Assert(organization.ProposalReleaseThreshold.MinimalApprovalThreshold >= 2,
        "Organization must require at least 2 approvals.");
    
    State.DeveloperFeeController.Value.RootController = input;
    State.DeveloperFeeController.Value.ParliamentController = null;
    State.DeveloperFeeController.Value.DeveloperController = null;
    return new Empty();
}
```

Apply similar validation to:
- `ChangeUserFeeController()` at line 70
- `ChangeMethodFeeController()` in ACS1 implementation
- Any other controller change functions

Add test cases verifying:
1. Rejection of single-member organizations
2. Rejection of organizations with MinimalApprovalThreshold < 2
3. Successful changes only with adequate governance structures

### Proof of Concept

**Initial State:**
- DeveloperFeeController.RootController = Association(2 members: Parliament + Developer, MinimalApprovalThreshold = 2)

**Attack Steps:**

1. Attacker creates trivial organization:
   - Call `AssociationContract.CreateOrganization()` with:
     - OrganizationMembers = [AttackerAddress]
     - MinimalApprovalThreshold = 1
     - MinimalVoteThreshold = 1
   - This passes validation (MinimalApprovalThreshold > 0)

2. Current RootController creates proposal:
   - Proposal calls `TokenContract.ChangeDeveloperController(attackerOrganization)`
   - Both Parliament and Developer approve (via social engineering or compromise)
   - Proposal executes

3. Result:
   - DeveloperFeeController.RootController = AttackerOrganization (1-of-1)
   - Attacker can now unilaterally call `UpdateCoefficientsForContract()`
   - Set all resource fee coefficients to 0 or extreme values
   - No multi-signature requirement remains

**Expected Behavior:**
`ChangeDeveloperController()` should reject organizations with insufficient governance thresholds.

**Actual Behavior:**
Any organization passing `CheckOrganizationExist()` is accepted, regardless of governance quality, enabling permanent degradation from 2-of-2 to 1-of-1 control.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L116-121)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-81)
```csharp
    private bool Validate(Organization organization)
    {
        if (organization.ProposerWhiteList.Empty() ||
            organization.ProposerWhiteList.AnyDuplicate() ||
            organization.OrganizationMemberList.Empty() ||
            organization.OrganizationMemberList.AnyDuplicate())
            return false;
        if (organization.OrganizationAddress == null || organization.OrganizationHash == null)
            return false;
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var organizationMemberCount = organization.OrganizationMemberList.Count();
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
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
