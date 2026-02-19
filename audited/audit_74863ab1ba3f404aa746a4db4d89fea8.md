### Title
Single Member Authority Escalation in Method Fee Control via 1-of-N Association Multi-Sig

### Summary
When `MethodFeeController.Value.OwnerAddress` is set to an Association organization with `MinimalApprovalThreshold=1`, a single compromised organization member can unilaterally control all method fees for the Profit contract. The authorization check in `SetMethodFee()` only validates that the sender is the organization address, without verifying the governance threshold strength, allowing single-member proposals to bypass intended multi-sig protections.

### Finding Description

The vulnerability exists in the `SetMethodFee()` function's authorization logic: [1](#0-0) 

This check only verifies that `Context.Sender` equals the `MethodFeeController.Value.OwnerAddress` but does not validate the governance strength of how that organization makes decisions.

The Association contract's validation logic permits organizations with `MinimalApprovalThreshold=1`: [2](#0-1) 

When an Association proposal is released, it executes with the organization's virtual address as the sender: [3](#0-2) 

The threshold checking logic only requires the approval count to meet the minimal threshold: [4](#0-3) 

Test evidence confirms a single member can create and approve their own proposal when thresholds are set to 1: [5](#0-4) 

**Root Cause**: The `SetMethodFee()` authorization model assumes that any transaction sent from the organization address represents legitimate multi-sig consensus, but it fails to enforce or verify the minimum governance threshold strength. Association organizations with `MinimalApprovalThreshold=1` enable single-member unilateral actions.

**Why Protections Fail**: 
- No validation of organization threshold configuration during `ChangeMethodFeeController()`
- No distinction between 1-of-N and M-of-N (M>1) governance models
- Same member can be in both proposer whitelist and member list, enabling self-proposal and self-approval

### Impact Explanation

**Direct Harm**: A compromised organization member gains complete control over method fees for all Profit contract operations, including:
- Setting arbitrarily high fees to make contract functions prohibitively expensive or effectively unusable
- Setting zero fees to eliminate transaction costs for specific methods, breaking the economic model
- Manipulating fees for competitive advantage or griefing attacks

**Affected Parties**:
- All users of the Profit contract who must pay method fees
- Protocol economics that depend on fee collection
- Governance legitimacy of the method fee controller system

**Severity Justification**: HIGH - This violates the fundamental invariant that multi-sig authority should require multiple approvals. A 1-of-N configuration that was intended for operational convenience becomes a single point of failure, allowing one compromised key to bypass all governance controls over critical fee parameters.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Be a member of the Association organization controlling method fees
- Be in the proposer whitelist (commonly all members have both roles)
- Have access to compromised or malicious member key

**Attack Complexity**: LOW
1. Create proposal to call `SetMethodFee` with malicious parameters
2. Approve own proposal (single transaction)
3. Release proposal (single transaction)
4. Malicious fees are immediately active

**Feasibility Conditions**:
- Organization must use `MinimalApprovalThreshold=1` and `MinimalVoteThreshold=1`
- This configuration is explicitly supported and tested in the codebase
- Administrators may choose this for operational speed without understanding security implications

**Detection Constraints**: Proposals and approvals are on-chain events, but by the time they're detected, the damage is done. The 3-transaction sequence can execute in seconds within a single block production cycle.

**Probability**: MEDIUM-HIGH if organizations use 1-of-N thresholds for convenience. The vulnerability is latent in the design and becomes exploitable immediately upon configuration of such a threshold.

### Recommendation

**Code-Level Mitigation**:

Add threshold validation in `ChangeMethodFeeController()`: [6](#0-5) 

After line 26, add validation:
```csharp
if (input.ContractAddress == State.AssociationContract.Value)
{
    var organization = State.AssociationContract.GetOrganization.Call(input.OwnerAddress);
    Assert(organization.ProposalReleaseThreshold.MinimalApprovalThreshold >= MINIMUM_SAFE_THRESHOLD,
        "Organization threshold too low for fee control authority.");
}
```

Define `MINIMUM_SAFE_THRESHOLD` constant (recommended: 2 or higher, or N/2 + 1 for N members).

**Invariant Checks**:
- Enforce minimum approval threshold ≥ 2 for any organization controlling method fees
- Consider requiring threshold ≥ (total_members / 2) + 1 for critical authorities
- Add similar checks for Parliament and Referendum organizations

**Test Cases**:
1. Attempt to set MethodFeeController to organization with `MinimalApprovalThreshold=1` (should fail)
2. Verify threshold requirement for all three organization types (Association, Parliament, Referendum)
3. Test that existing strong multi-sig organizations (threshold ≥ 2) continue to function
4. Regression test for ChangeMethodFeeController with various threshold configurations

### Proof of Concept

**Required Initial State**:
1. Deploy Profit and Association contracts
2. Create Association organization with:
   - `MinimalApprovalThreshold = 1`
   - `MinimalVoteThreshold = 1`
   - `OrganizationMembers = [Attacker, Member2, Member3]`
   - `ProposerWhiteList = [Attacker, Member2, Member3]`
3. Set `MethodFeeController.OwnerAddress` to this organization address

**Attack Transaction Sequence**:

**Transaction 1** - Attacker creates proposal:
```
AssociationContract.CreateProposal({
  ToAddress: ProfitContractAddress,
  ContractMethodName: "SetMethodFee",
  Params: { MethodName: "CreateScheme", Fees: [{ Symbol: "ELF", BasicFee: 999999999999 }] },
  OrganizationAddress: WeakMultiSigOrgAddress
})
→ Returns: proposalId
```

**Transaction 2** - Attacker approves own proposal:
```
AssociationContract.Approve(proposalId)
→ Proposal.Approvals.Count = 1 (meets MinimalApprovalThreshold)
```

**Transaction 3** - Attacker releases proposal:
```
AssociationContract.Release(proposalId)
→ Executes SetMethodFee with Context.Sender = WeakMultiSigOrgAddress
→ Authorization check passes
→ Method fees updated to malicious values
```

**Expected Result**: Only with proper multi-sig (≥2 approvals), fees should be modifiable.

**Actual Result**: Single member unilaterally controls method fees, bypassing multi-sig intent.

**Success Condition**: After Transaction 3, `ProfitContract.GetMethodFee("CreateScheme")` returns the attacker's malicious fee value (999999999999), proving single-member control.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L16-16)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L22-31)
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-52)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-74)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L742-749)
```csharp
        var minimalApproveThreshold = 1;
        var minimalVoteThreshold = 1;
        var maximalAbstentionThreshold = 1;
        var maximalRejectionThreshold = 1;
        var organizationAddress = await CreateOrganizationAsync(minimalApproveThreshold, minimalVoteThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, Reviewer1);
        var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
        await ApproveAsync(Reviewer1KeyPair, proposalId);
```
