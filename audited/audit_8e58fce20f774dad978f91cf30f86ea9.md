### Title
Governance Controller Downgrade Allows Permission Escalation to Single-Signature Authority

### Summary
The `ChangeMaximumMinersCountController()` function validates only that the new controller organization exists, but does not enforce any security properties or threshold requirements. This allows a current multi-signature Parliament controller to replace itself with a permissive single-member Association organization, effectively bypassing multi-signature governance restrictions on critical consensus parameters like maximum miner count and miner increase intervals.

### Finding Description

The vulnerability exists in the `ChangeMaximumMinersCountController()` function which allows changing the authority that controls consensus parameters. [1](#0-0) 

The function performs only two validations:
1. Verifies the sender is the current controller's owner address
2. Checks that the new organization exists via `CheckOrganizationExist()` [2](#0-1) 

The `CheckOrganizationExist()` function only validates that the organization address exists in the specified authorization contract (Parliament, Association, or Referendum), but does not validate any security properties such as approval thresholds or member counts. [3](#0-2) 

**Root Cause**: The Association contract allows creating organizations with minimal security constraints - as low as 1 member with a threshold of 1 approval. [4](#0-3) 

The validation logic only requires `MinimalApprovalThreshold > 0`, meaning a single-member, single-approval organization is valid. This contrasts sharply with Parliament's default organization which requires 66.67% approval and 75% participation from current blockchain miners. [5](#0-4) 

Parliament also restricts voting to actual miners through strict authorization checks: [6](#0-5) 

**Why Protections Fail**: The function assumes that any existing organization provides adequate security, without validating that the new controller maintains or strengthens governance properties compared to the current controller.

### Impact Explanation

**Concrete Harm**:
The compromised controller gains unilateral control over critical consensus parameters:

1. **SetMaximumMinersCount**: Can arbitrarily set the maximum number of miners, directly affecting consensus security and decentralization. [7](#0-6) 

This immediately propagates to the Election contract, affecting which candidates become miners in the next term by controlling `State.MinersCount.Value`.

2. **SetMinerIncreaseInterval**: Can manipulate the rate at which miners are added to the network over time. [8](#0-7) 

**Who is Affected**: The entire blockchain network, as consensus parameter manipulation can:
- Centralize consensus by reducing miner count
- Destabilize the network by artificially inflating miner count beyond capable nodes
- Manipulate validator selection dynamics

**Severity Justification**: HIGH - This is a governance escalation vulnerability that converts a multi-signature, miner-controlled authority into a single-signature authority, fundamentally undermining the decentralized governance model and compromising consensus integrity.

### Likelihood Explanation

**Attacker Capabilities Required**: 
- Initial control of the current Parliament controller (through legitimate governance proposal and approval)
- Ability to create an Association organization (public function, no special privileges required)
- Ability to submit one transaction calling `ChangeMaximumMinersCountController()`

**Attack Complexity**: LOW
- No complex transaction sequences required
- No timing dependencies
- No need to exploit race conditions or reentrancy

**Feasibility Conditions**:
1. Attacker gains temporary majority in Parliament (realistic through election manipulation, coalition building, or compromise of miner keys)
2. Parliament approves a single malicious proposal to change the controller
3. Once changed, the new single-sig controller has permanent unilateral authority until changed again

**Detection/Operational Constraints**: 
- The controller change is a visible on-chain transaction
- However, once executed, subsequent actions by the new controller require no approvals
- No time locks or delays provide opportunity for intervention

**Probability**: MEDIUM-HIGH - While gaining initial Parliament control requires effort, once achieved, the downgrade is trivial and irreversible without re-gaining multi-sig control.

### Recommendation

**Code-Level Mitigation**:
Add validation in `ChangeMaximumMinersCountController()` to enforce minimum security properties:

```csharp
public override Empty ChangeMaximumMinersCountController(AuthorityInfo input)
{
    RequiredMaximumMinersCountControllerSet();
    AssertSenderAddressWith(State.MaximumMinersCountController.Value.OwnerAddress);
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");
    
    // NEW: Validate minimum governance security
    Assert(ValidateGovernanceSecurity(input), 
        "New controller must maintain minimum governance security properties.");
    
    State.MaximumMinersCountController.Value = input;
    return new Empty();
}

private bool ValidateGovernanceSecurity(AuthorityInfo authorityInfo)
{
    // For Parliament: Always accept (miners are trusted)
    if (authorityInfo.ContractAddress == State.ParliamentContract.Value)
        return true;
        
    // For Association: Require minimum threshold
    if (authorityInfo.ContractAddress == GetAssociationContractAddress())
    {
        var org = GetAssociationOrganization(authorityInfo.OwnerAddress);
        return org.ProposalReleaseThreshold.MinimalApprovalThreshold >= MinimumRequiredApprovals &&
               org.OrganizationMemberList.Count() >= MinimumRequiredMembers &&
               org.ProposalReleaseThreshold.MinimalVoteThreshold >= MinimumRequiredVoteThreshold;
    }
    
    // For Referendum: Validate token lock requirements
    if (authorityInfo.ContractAddress == GetReferendumContractAddress())
    {
        var org = GetReferendumOrganization(authorityInfo.OwnerAddress);
        return org.TokenSymbol == ExpectedGovernanceToken &&
               org.ProposalReleaseThreshold.MinimalApprovalThreshold >= MinimumTokenThreshold;
    }
    
    return false;
}
```

**Invariant Checks to Add**:
1. Controller changes must maintain or increase approval threshold requirements
2. Controller changes must maintain or increase minimum member/voter counts
3. Association controllers must require at least 3 members with 2/3 approval threshold
4. Add a time-lock period before controller changes take effect to allow emergency response

**Test Cases**:
1. Test that changing from Parliament to single-member Association is rejected
2. Test that changing from multi-sig Association to lower-threshold Association is rejected
3. Test that changing to Parliament from Association is accepted
4. Test that changing to equal-or-higher threshold Association is accepted
5. Test the time-lock delay mechanism

### Proof of Concept

**Initial State**:
- AEDPoS contract initialized with default Parliament controller
- Parliament default organization controls `MaximumMinersCountController` with high thresholds (6667/10000 approval required from miners)

**Attack Steps**:

1. **Create Malicious Association Organization**:
```
Attacker calls AssociationContract.CreateOrganization({
    OrganizationMemberList: [AttackerAddress],
    ProposalReleaseThreshold: {
        MinimalApprovalThreshold: 1,
        MinimalVoteThreshold: 1,
        MaximalAbstentionThreshold: 0,
        MaximalRejectionThreshold: 0
    },
    ProposerWhiteList: [AttackerAddress]
})
→ Returns: MaliciousOrgAddress
```

2. **Gain Parliament Control & Propose Controller Change**:
```
Create Parliament proposal to call:
AEDPoSContract.ChangeMaximumMinersCountController({
    OwnerAddress: MaliciousOrgAddress,
    ContractAddress: AssociationContractAddress
})
```

3. **Parliament Approves & Releases Proposal**:
```
Miners approve proposal (requires 6667/10000 approval)
Parliament.Release(proposalId)
→ Controller changed to single-sig Association
```

4. **Exploit Unilateral Control**:
```
Attacker (now sole controller) calls:
AEDPoSContract.SetMaximumMinersCount(3)
→ Succeeds immediately, no multi-sig required
→ Next term will have only 3 miners regardless of candidates
```

**Expected vs Actual Result**:
- **Expected**: Controller changes should require maintaining governance security properties
- **Actual**: Any valid organization can become controller, including single-sig arrangements

**Success Condition**: 
After step 3, `GetMaximumMinersCountController()` returns the attacker's single-member Association organization, and `SetMaximumMinersCount()` succeeds when called by the attacker alone without any approvals from other parties.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L45-54)
```csharp
    public override Empty ChangeMaximumMinersCountController(AuthorityInfo input)
    {
        RequiredMaximumMinersCountControllerSet();
        AssertSenderAddressWith(State.MaximumMinersCountController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MaximumMinersCountController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L56-64)
```csharp
    public override Empty SetMinerIncreaseInterval(Int64Value input)
    {
        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set miner increase interval.");
        Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
        State.MinerIncreaseInterval.Value = input.Value;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L83-88)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-9)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L112-140)
```csharp
    private Address GetAndCheckActualParliamentMemberAddress()
    {
        var currentParliament = GetCurrentMinerList();

        if (currentParliament.Any(r => r.Equals(Context.Sender))) return Context.Sender;

        if (State.ElectionContract.Value == null)
        {
            var electionContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
            if (electionContractAddress == null)
                // Election Contract not deployed - only possible in test environment.
                throw new AssertionException("Unauthorized sender.");

            State.ElectionContract.Value = electionContractAddress;
        }

        var managedPubkey = State.ElectionContract.GetManagedPubkeys.Call(Context.Sender);
        if (!managedPubkey.Value.Any()) throw new AssertionException("Unauthorized sender.");

        if (managedPubkey.Value.Count > 1)
            throw new AssertionException("Admin with multiple managed pubkeys cannot handle proposal.");

        var actualMemberAddress = Address.FromPublicKey(managedPubkey.Value.Single().ToByteArray());
        if (!currentParliament.Any(r => r.Equals(actualMemberAddress)))
            throw new AssertionException("Unauthorized sender.");

        return actualMemberAddress;
    }
```
