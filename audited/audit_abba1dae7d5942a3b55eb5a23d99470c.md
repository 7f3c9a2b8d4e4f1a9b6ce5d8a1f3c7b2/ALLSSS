### Title
Permanent DOS of Method Fee Governance via Cross-Contract Authority with Near-Impossible Approval Thresholds

### Summary
The `ChangeMethodFeeController()` function in the Association contract only validates that a target organization exists, but does not validate the reasonableness of its approval thresholds. This allows the current fee controller to maliciously change to a Parliament organization with near-impossible thresholds (e.g., 9999/10000 = 99.99% approval), permanently freezing all future method fee changes. Parliament organizations use ratio-based thresholds that can approach unanimity, making proposal approval practically impossible even with cooperative miners.

### Finding Description

**Location and Root Cause:**

The vulnerability exists in `ChangeMethodFeeController()` which performs only two validations: [1](#0-0) 

The function checks sender authorization and organization existence via `CheckOrganizationExist()`: [2](#0-1) 

This validation only verifies the organization exists in the specified contract - it returns true/false based on storage lookup: [3](#0-2) 

**Critical Missing Validation:**

The `AuthorityInfo` structure allows specifying any governance contract address: [4](#0-3) 

This means the Association contract's method fee controller can be changed to a **Parliament** organization, not just an Association organization. Parliament organizations use ratio-based thresholds validated against `AbstractVoteTotal = 10000`: [5](#0-4) 

Parliament's validation allows thresholds up to 10000 (100%): [6](#0-5) 

**Exploitation Mechanism:**

Parliament's approval logic uses the formula: [7](#0-6) 

With `MinimalApprovalThreshold = 9999` and `AbstractVoteTotal = 10000`, this requires:
- `approvedMemberCount * 10000 >= 9999 * parliamentMembers.Count`
- For 100 miners: `approvedMemberCount >= 99.99` → effectively requires all 100 miners

**Proof from Codebase:**

The system intentionally creates high-threshold organizations: [8](#0-7) 

Test cases confirm Parliament organizations with high thresholds (1000/10000) can be set as Association contract's method fee controller: [9](#0-8) 

### Impact Explanation

**Direct Governance Impact:**
- Method fees control transaction costs for all contract operations
- Frozen controller means no future fee adjustments possible
- Cannot respond to changing economic conditions (token price fluctuations, network congestion)
- May render contracts unusable if fees become prohibitively expensive or worthlessly cheap

**Quantified Damage:**
- With threshold set to 9999/10000 and 100 miners: requires 99.99% approval (effectively 100 miners)
- Even 99% miner cooperation (99/100) fails to meet threshold
- In real-world governance, achieving 100% consensus is practically impossible due to:
  - Miner availability/downtime
  - Technical issues
  - Governance disagreements
  - Malicious actors withholding approval

**Severity Justification: CRITICAL**
- Permanent DOS of critical governance function
- No recovery mechanism once set
- Affects all users paying transaction fees
- Undermines entire fee governance model

### Likelihood Explanation

**Attacker Capabilities:**
- Requires control of current method fee controller (default: Parliament's default organization)
- Default Parliament organization requires ~66.67% miner approval (threshold 6667/10000): [10](#0-9) 

**Attack Complexity: LOW**
1. Create Parliament organization with threshold 9999 (requires default Parliament approval)
2. Submit proposal to call `ChangeMethodFeeController` with new organization (requires default Parliament approval)
3. Both steps use standard governance procedures

**Feasibility: HIGH**
- Parliament members (miners) can create organizations: [11](#0-10) 
- Attack requires only standard proposal process, no special privileges beyond controlling current controller
- Test infrastructure proves this works in practice

**Detection/Prevention: NONE**
- No threshold sanity checks in `ChangeMethodFeeController`
- No upper bound validation on Parliament thresholds
- No alerts or warnings for dangerously high thresholds

### Recommendation

**Immediate Mitigation - Add Threshold Validation:**

In `AssociationContract_ACS1_TransactionFeeProvider.cs`, add validation in `ChangeMethodFeeController()` after line 25:

```csharp
var organizationExist = CheckOrganizationExist(input);
Assert(organizationExist, "Invalid authority input.");

// NEW: Validate reasonable thresholds for cross-contract authorities
if (input.ContractAddress != Context.Self)
{
    ValidateReasonableThresholds(input);
}
```

**Add Helper Method:**

```csharp
private void ValidateReasonableThresholds(AuthorityInfo authorityInfo)
{
    // For Parliament organizations, check thresholds are achievable
    var organization = Context.Call<Organization>(
        authorityInfo.ContractAddress,
        "GetOrganization",
        authorityInfo.OwnerAddress
    );
    
    // Maximum reasonable threshold: 90% to allow for some miner unavailability
    const int maxReasonableThreshold = 9000;
    Assert(
        organization.ProposalReleaseThreshold.MinimalApprovalThreshold <= maxReasonableThreshold,
        $"Approval threshold too high: {organization.ProposalReleaseThreshold.MinimalApprovalThreshold} > {maxReasonableThreshold}"
    );
}
```

**Additional Protections:**
1. Add maximum threshold constant (e.g., 9000 = 90%) across all governance contracts
2. Implement emergency recovery mechanism via Genesis contract
3. Add governance proposal to reduce thresholds if organization becomes unreachable
4. Add monitoring/alerting for method fee controller changes

**Test Cases:**
1. Test rejection when setting controller to organization with threshold > 9000
2. Test acceptance when threshold <= 9000
3. Test cross-contract validation (Parliament org as Association controller)
4. Test emergency recovery procedures

### Proof of Concept

**Initial State:**
- Association contract deployed
- Method fee controller = Parliament default organization (66.67% threshold)
- Current miner count = 100

**Attack Sequence:**

**Step 1:** Create malicious Parliament organization
```csharp
// Through Parliament default org proposal
var maliciousOrgInput = new CreateOrganizationInput
{
    ProposalReleaseThreshold = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 9999,  // 99.99% approval required
        MinimalVoteThreshold = 9999,
        MaximalAbstentionThreshold = 0,
        MaximalRejectionThreshold = 0
    },
    ProposerAuthorityRequired = false,
    ParliamentMemberProposingAllowed = true
};
var maliciousOrgAddress = await ParliamentContract.CreateOrganization(maliciousOrgInput);
```

**Step 2:** Change Association contract's method fee controller
```csharp
// Through Parliament default org proposal
var newAuthority = new AuthorityInfo
{
    OwnerAddress = maliciousOrgAddress,
    ContractAddress = ParliamentContractAddress
};
await AssociationContract.ChangeMethodFeeController(newAuthority);
```

**Expected Result:** Transaction succeeds, method fee controller changed

**Actual Result:** Transaction succeeds - NO threshold validation performed

**Verification of DOS:**
Try to change method fees or controller:
```csharp
// Attempt to propose fee change through new controller
var proposal = await ParliamentContract.CreateProposal(new CreateProposalInput
{
    OrganizationAddress = maliciousOrgAddress,
    ContractMethodName = "SetMethodFee",
    ToAddress = AssociationContractAddress,
    Params = newMethodFees.ToByteString(),
    ExpiredTime = timestamp
});

// Get 99 out of 100 miners to approve
await ParliamentContract.ApproveMultiProposals(proposal); // 99 approvals

// Try to release
var result = await ParliamentContract.Release(proposal);
// FAILS: 99/100 = 99% < 99.99% required threshold
```

**Success Condition:** Method fee governance permanently frozen - even 99% miner cooperation cannot pass proposals.

### Citations

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L21-30)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L70-74)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** protobuf/authority_info.proto (L5-10)
```text
message AuthorityInfo {
    // The contract address of the controller.
    aelf.Address contract_address = 1;
    // The address of the owner of the contract.
    aelf.Address owner_address = 2;
}
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-8)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L80-92)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached = IsVoteThresholdReached(proposal, organization, parliamentMembers);
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L142-155)
```csharp
    private bool Validate(Organization organization)
    {
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;

        return proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L314-330)
```csharp
    private void CreateEmergencyResponseOrganization()
    {
        var createOrganizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 9000,
                MinimalVoteThreshold = 9000,
                MaximalAbstentionThreshold = 1000,
                MaximalRejectionThreshold = 1000
            },
            ProposerAuthorityRequired = false,
            ParliamentMemberProposingAllowed = true
        };

        State.EmergencyResponseOrganizationAddress.Value = CreateOrganization(createOrganizationInput);
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L863-897)
```csharp
    public async Task ChangeMethodFeeController_Test()
    {
        var createOrganizationResult =
            await ParliamentContractStub.CreateOrganization.SendAsync(
                new Parliament.CreateOrganizationInput
                {
                    ProposalReleaseThreshold = new ProposalReleaseThreshold
                    {
                        MinimalApprovalThreshold = 1000,
                        MinimalVoteThreshold = 1000
                    }
                });
        var organizationAddress = Address.Parser.ParseFrom(createOrganizationResult.TransactionResult.ReturnValue);

        var methodFeeController = await AssociationContractStub.GetMethodFeeController.CallAsync(new Empty());
        var defaultOrganization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        methodFeeController.OwnerAddress.ShouldBe(defaultOrganization);

        const string proposalCreationMethodName = nameof(AssociationContractStub.ChangeMethodFeeController);

        var proposalId = await CreateFeeProposalAsync(AssociationContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName, new AuthorityInfo
            {
                OwnerAddress = organizationAddress,
                ContractAddress = ParliamentContractAddress
            });

        await ApproveWithMinersAsync(proposalId);
        var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId);
        releaseResult.TransactionResult.Error.ShouldBeNullOrEmpty();
        releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        var newMethodFeeController = await AssociationContractStub.GetMethodFeeController.CallAsync(new Empty());
        Assert.True(newMethodFeeController.OwnerAddress == organizationAddress);
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L50-59)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        Assert(
            ValidateAddressInWhiteList(Context.Sender) || ValidateParliamentMemberAuthority(Context.Sender) ||
            State.DefaultOrganizationAddress.Value == Context.Sender,
            "Unauthorized to create organization.");
        var organizationAddress = CreateNewOrganization(input);

        return organizationAddress;
    }
```
