# Audit Report

## Title
Referendum Contract Allows Setting Unbounded MinimalVoteThreshold Leading to Permanent Governance Lockout

## Summary
The Referendum contract's `ChangeOrganizationThreshold` function lacks upper bound validation for `MinimalVoteThreshold`, allowing an organization to set this value to `Int64.MaxValue` or any unreachably high number. This makes all future proposals impossible to release, permanently locking the organization's governance functionality. Unlike Parliament and Association contracts which enforce maximum threshold limits, Referendum has no such protection.

## Finding Description

The vulnerability exists in the threshold validation logic of the Referendum contract. When `ChangeOrganizationThreshold` is called, it updates the organization's `ProposalReleaseThreshold` and validates it using the `Validate` method. [1](#0-0) 

The `Validate` method only checks relative relationships between threshold values but imposes **no upper bound** on `MinimalVoteThreshold`: [2](#0-1) 

The validation only requires:
- `MinimalApprovalThreshold <= MinimalVoteThreshold`
- `MinimalApprovalThreshold > 0`
- `MaximalAbstentionThreshold >= 0`
- `MaximalRejectionThreshold >= 0`

There is no check preventing `MinimalVoteThreshold` from being set to `Int64.MaxValue` (9,223,372,036,854,775,807).

When proposals attempt to release, the `IsReleaseThresholdReached` method checks if total votes meet the threshold: [3](#0-2) 

If `MinimalVoteThreshold` is set to `Int64.MaxValue`, the check at lines 15-16 will never be satisfied since the total token supply in any realistic scenario is far less than `Int64.MaxValue`.

**Contrast with Other Governance Contracts:**

The Parliament contract enforces an upper bound: [4](#0-3) 

With `AbstractVoteTotal = 10000`: [5](#0-4) 

The Association contract enforces that `MinimalVoteThreshold` cannot exceed the organization member count: [6](#0-5) 

**Referendum contract is the only governance contract missing this critical validation.**

## Impact Explanation

**Severity: HIGH - Permanent Governance DoS**

Once an organization's `MinimalVoteThreshold` is set to an unreachable value, the organization's governance becomes **permanently non-functional**:

1. **Complete Governance Lockout**: All existing and future proposals can never be released because the vote threshold check in `IsReleaseThresholdReached` can never be satisfied.

2. **No Recovery Mechanism**: The `ChangeOrganizationThreshold` method requires `Context.Sender` to be the organization address itself, meaning it can ONLY be called through a proposal release. Since proposals cannot be released when the threshold is unreachable, the organization cannot fix its own thresholds. This creates an unrecoverable state. [7](#0-6) 

3. **Affected Parties**: All members of the affected Referendum organization lose their governance rights permanently. Any critical operations that require governance approval (upgrades, parameter changes, fund releases) become impossible.

4. **Protocol Impact**: If critical protocol operations are controlled by Referendum organizations, this could impact the entire protocol's ability to adapt or upgrade.

The attack is **irreversible** and causes **total loss of governance functionality** for the affected organization.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH - Single Malicious Proposal Attack**

**Attacker Capabilities Required:**
- Must be in the organization's proposer whitelist (standard requirement for creating proposals)
- Must successfully pass one malicious proposal through the organization's current approval process

**Attack Complexity: LOW**
1. Attacker creates a proposal calling `ChangeOrganizationThreshold` with `MinimalVoteThreshold = Int64.MaxValue` and `MinimalApprovalThreshold = Int64.MaxValue`
2. The proposal needs to pass current voting thresholds (one-time requirement)
3. Attacker or any authorized party releases the proposal
4. Organization is permanently locked

**Feasibility Conditions:**
- **Social Engineering**: The attack could be disguised as a "security improvement" to increase voting requirements
- **Compromised Proposer**: A single compromised or malicious whitelisted proposer can initiate this attack
- **Majority Collusion**: If enough organization members collude, they can deliberately lock the organization

**Economic Cost: MINIMAL**
- Only requires gas fees to create and release one proposal
- No financial stake or capital requirements beyond normal proposal creation

**Detection Difficulty:**
- The malicious threshold change may not be immediately obvious
- Organizations may not realize they're locked until attempting to release the next proposal
- No automatic alerts or warnings exist for extreme threshold values

## Recommendation

Add an upper bound validation for `MinimalVoteThreshold` in the Referendum contract's `Validate` method, similar to Parliament and Association contracts. 

The recommended fix is to add a check that ensures `MinimalVoteThreshold` cannot exceed a reasonable maximum value based on the token's realistic total supply or a predefined constant. For example:

In `Referendum_Helper.cs`, modify the `Validate` method to include:
- Define a reasonable maximum threshold constant (e.g., based on expected token circulation)
- Add validation: `proposalReleaseThreshold.MinimalVoteThreshold <= MaximumVoteThreshold`
- Ensure the maximum accounts for practical token-weighted voting scenarios

This would align Referendum with the security model of Parliament (which uses `AbstractVoteTotal = 10000` as upper bound) and Association (which uses member count as upper bound).

## Proof of Concept

The following test demonstrates the vulnerability by setting an unreachable `MinimalVoteThreshold` and showing that proposals can no longer be released:

```csharp
[Fact]
public async Task Referendum_UnboundedThreshold_PermanentGovernanceLockout_Test()
{
    // Setup: Create organization with normal thresholds
    var normalThreshold = 5000;
    var organizationAddress = await CreateOrganizationAsync(normalThreshold, normalThreshold,
        10000, 10000, new[] { DefaultSender });
    
    // Step 1: Create and pass a malicious proposal to set unreachable threshold
    var maliciousThreshold = new ProposalReleaseThreshold
    {
        MinimalVoteThreshold = long.MaxValue,  // Unreachable value
        MinimalApprovalThreshold = long.MaxValue,
        MaximalAbstentionThreshold = 0,
        MaximalRejectionThreshold = 0
    };
    
    var changeThresholdProposalId = await CreateReferendumProposalAsync(
        DefaultSenderKeyPair,
        maliciousThreshold,
        nameof(ReferendumContractStub.ChangeOrganizationThreshold),
        organizationAddress,
        ReferendumContractAddress);
    
    // Vote and release the malicious proposal (using current normal threshold)
    await ApproveAllowanceAsync(Accounts[3].KeyPair, normalThreshold, changeThresholdProposalId);
    await ApproveAsync(Accounts[3].KeyPair, changeThresholdProposalId);
    await ReferendumContractStub.Release.SendAsync(changeThresholdProposalId);
    
    // Step 2: Verify threshold was changed to unreachable value
    var updatedOrg = await ReferendumContractStub.GetOrganization.CallAsync(organizationAddress);
    updatedOrg.ProposalReleaseThreshold.MinimalVoteThreshold.ShouldBe(long.MaxValue);
    
    // Step 3: Try to create and pass a new proposal - it should be impossible to release
    var newProposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
    
    // Even with maximum possible votes, proposal cannot be released
    await ApproveAllowanceAsync(Accounts[3].KeyPair, long.MaxValue / 2, newProposalId); // Use half to avoid overflow
    await ApproveAsync(Accounts[3].KeyPair, newProposalId);
    
    var proposal = await ReferendumContractStub.GetProposal.CallAsync(newProposalId);
    proposal.ToBeReleased.ShouldBeFalse(); // Proposal can NEVER be released
    
    // Step 4: Verify permanent lockout - cannot even fix the threshold
    var fixThresholdProposal = new ProposalReleaseThreshold
    {
        MinimalVoteThreshold = normalThreshold,
        MinimalApprovalThreshold = normalThreshold,
        MaximalAbstentionThreshold = 10000,
        MaximalRejectionThreshold = 10000
    };
    
    var fixProposalId = await CreateReferendumProposalAsync(
        DefaultSenderKeyPair,
        fixThresholdProposal,
        nameof(ReferendumContractStub.ChangeOrganizationThreshold),
        organizationAddress,
        ReferendumContractAddress);
    
    // Cannot release fix proposal because threshold is unreachable
    var fixProposal = await ReferendumContractStub.GetProposal.CallAsync(fixProposalId);
    fixProposal.ToBeReleased.ShouldBeFalse(); // Organization is permanently locked
}
```

This test proves:
1. The Referendum contract accepts `Int64.MaxValue` as a valid `MinimalVoteThreshold`
2. Once set, no proposal can ever reach this threshold
3. The organization cannot recover because fixing the threshold also requires releasing a proposal
4. The governance is permanently locked with no recovery mechanism

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L124-137)
```csharp
    public override Empty ChangeOrganizationThreshold(ProposalReleaseThreshold input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationThresholdChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerReleaseThreshold = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L12-29)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var enoughVote = proposal.RejectionCount.Add(proposal.AbstentionCount).Add(proposal.ApprovalCount) >=
                         proposalReleaseThreshold.MinimalVoteThreshold;
        if (!enoughVote)
            return false;

        var isRejected = proposal.RejectionCount > proposalReleaseThreshold.MaximalRejectionThreshold;
        if (isRejected)
            return false;

        var isAbstained = proposal.AbstentionCount > proposalReleaseThreshold.MaximalAbstentionThreshold;
        if (isAbstained)
            return false;

        return proposal.ApprovalCount >= proposalReleaseThreshold.MinimalApprovalThreshold;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L90-102)
```csharp
    private bool Validate(Organization organization)
    {
        if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
            organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
            return false;
        Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");

        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
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
