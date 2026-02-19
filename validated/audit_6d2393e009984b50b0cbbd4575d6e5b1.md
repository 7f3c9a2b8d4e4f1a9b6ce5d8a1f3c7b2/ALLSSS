# Audit Report

## Title
ProposerWhiteList Desynchronization in ChangeMember() Breaking Proposal Authorization

## Summary
The `ChangeMember()` function in the Association contract updates the `OrganizationMemberList` but fails to synchronize the `ProposerWhiteList`, creating an authorization desynchronization vulnerability. When a member is replaced, the removed member retains proposal creation rights without voting rights, while the new member gains voting rights without proposal creation rights, breaking the intended governance authorization model.

## Finding Description

The vulnerability exists in the `ChangeMember()` function which only modifies the `OrganizationMemberList` without updating the `ProposerWhiteList`. [1](#0-0) 

An Association organization maintains two separate authorization lists:
- `OrganizationMemberList`: controls who can vote (approve/reject/abstain) on proposals
- `ProposerWhiteList`: controls who can create proposals

When `ChangeMember(input)` executes, it removes `input.OldMember` from `OrganizationMemberList` and adds `input.NewMember` to `OrganizationMemberList`, but the `ProposerWhiteList` remains completely unchanged, leaving the old member still authorized to create proposals.

Proposal creation authorization is enforced by `AssertIsAuthorizedProposer()` which only checks `ProposerWhiteList` membership. [2](#0-1) 

Voting authorization is enforced by `AssertIsAuthorizedOrganizationMember()` which only checks `OrganizationMemberList` membership. [3](#0-2) 

The `Validate()` function does not enforce consistency between the two authorization lists - it only verifies that neither list is empty or contains duplicates, and that threshold constraints are satisfied, but never checks that `ProposerWhiteList` members are also in `OrganizationMemberList`. [4](#0-3) 

Both `CreateProposal()` and `CreateProposalBySystemContract()` only verify `ProposerWhiteList` membership through `AssertIsAuthorizedProposer()`, not `OrganizationMemberList` membership. [5](#0-4) 

**Attack Scenario:**
1. Organization has member Bob in both `OrganizationMemberList` and `ProposerWhiteList`
2. Organization passes proposal to call `ChangeMember({OldMember: Bob, NewMember: Dave})`
3. Post-execution state: Bob removed from `OrganizationMemberList`, Dave added to `OrganizationMemberList`, but `ProposerWhiteList` unchanged (still contains Bob)
4. Bob can now call `CreateProposal()` (passes `ProposerWhiteList` check) but cannot vote via `Approve()/Reject()/Abstain()` (fails `OrganizationMemberList` check)
5. Dave can vote via `Approve()/Reject()/Abstain()` (passes `OrganizationMemberList` check) but cannot call `CreateProposal()` (fails `ProposerWhiteList` check)

## Impact Explanation

This vulnerability breaks a critical authorization invariant of the Association governance system:

1. **Authorization Bypass**: A removed/replaced member retains proposal creation rights, allowing them to continue influencing governance by creating proposals they should no longer be authorized to create. If the member was removed due to becoming untrusted or having their key compromised, this is a significant security risk.

2. **Incomplete Privilege Transfer**: The new member who replaced the old member gains voting rights but lacks proposal creation rights, preventing them from exercising the full governance authority that the replacement was intended to grant.

3. **Operational Complexity**: Organizations must perform two separate governance actions (`ChangeMember` + `ChangeOrganizationProposerWhiteList`) to properly replace a proposer, significantly increasing complexity and the risk of incomplete transitions. [6](#0-5) 

4. **Silent Failure**: The contract provides no warnings, events, or validation failures when this desynchronization occurs, allowing the vulnerable state to persist undetected.

The severity is **Medium** because:
- It breaks authorization invariants and enables unauthorized proposal creation
- It does NOT directly steal funds or manipulate token balances
- Proposals still require approval thresholds from current members to execute
- Can be mitigated by separately calling `ChangeOrganizationProposerWhiteList()`
- Requires governance action to trigger (not exploitable by external attackers directly)

## Likelihood Explanation

This vulnerability has **High** likelihood of occurrence:

1. **Common Scenario**: Organizations frequently need to replace members who leave, become inactive, are compromised, or lose trust. Member replacement is a routine governance operation, and having departing members in the `ProposerWhiteList` is a standard configuration.

2. **Entry Point Accessibility**: `ChangeMember()` is designed to be callable by the organization itself (`Context.Sender` must equal the organization address), which is the standard mechanism for organizations to modify their membership through approved governance proposals.

3. **Non-Obvious Requirement**: The need to separately update `ProposerWhiteList` is not enforced by the contract, not checked by validation logic, and not documented in the function signature or error messages. Organizations naturally assume that "changing a member" includes transferring all their privileges.

4. **Operational Friction**: Properly replacing a proposer requires two separate governance proposals and voting rounds (first `ChangeMember`, then `ChangeOrganizationProposerWhiteList`), significantly increasing the likelihood that only the first step is completed before being forgotten or deprioritized.

5. **No Automated Detection**: The contract emits a `MemberChanged` event but provides no indication that the `ProposerWhiteList` is now inconsistent with `OrganizationMemberList`. There are no warnings, validation failures, or alerts to notify organizations of the desynchronized state.

## Recommendation

Add automatic synchronization of `ProposerWhiteList` in `ChangeMember()`:

```csharp
public override Empty ChangeMember(ChangeMemberInput input)
{
    var organization = State.Organizations[Context.Sender];
    Assert(organization != null, "Organization not found.");
    var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
    Assert(removeResult, "Remove member failed.");
    organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
    
    // NEW: Synchronize ProposerWhiteList if OldMember was a proposer
    if (organization.ProposerWhiteList.Contains(input.OldMember))
    {
        organization.ProposerWhiteList.Proposers.Remove(input.OldMember);
        organization.ProposerWhiteList.Proposers.Add(input.NewMember);
    }
    
    Assert(Validate(organization), "Invalid organization.");
    State.Organizations[Context.Sender] = organization;
    Context.Fire(new MemberChanged
    {
        OrganizationAddress = Context.Sender,
        OldMember = input.OldMember,
        NewMember = input.NewMember
    });
    return new Empty();
}
```

Alternatively, enhance the `Validate()` function to enforce that `ProposerWhiteList` is a subset of `OrganizationMemberList`:

```csharp
private bool Validate(Organization organization)
{
    if (organization.ProposerWhiteList.Empty() ||
        organization.ProposerWhiteList.AnyDuplicate() ||
        organization.OrganizationMemberList.Empty() ||
        organization.OrganizationMemberList.AnyDuplicate())
        return false;
        
    // NEW: Ensure ProposerWhiteList members are in OrganizationMemberList
    if (organization.ProposerWhiteList.Proposers.Any(p => 
        !organization.OrganizationMemberList.Contains(p)))
        return false;
    
    if (organization.OrganizationAddress == null || organization.OrganizationHash == null)
        return false;
    // ... rest of validation
}
```

## Proof of Concept

This vulnerability can be demonstrated with a test showing that after `ChangeMember()`, the old member can still create proposals but cannot vote, while the new member can vote but cannot create proposals.

**Notes**

This is a governance authorization desynchronization issue specific to the Association contract. The vulnerability requires governance-level access to trigger (organization must approve calling `ChangeMember()`), but once triggered, it creates a persistent authorization inconsistency that violates the expected security model. Organizations that frequently rotate members are particularly at risk of encountering this issue during routine governance operations.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L107-121)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
    }

    public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Not authorized to propose.");
        AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);
        var proposalId = CreateNewProposal(input.ProposalInput);
        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L218-231)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposerWhiteList = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L248-264)
```csharp
    public override Empty ChangeMember(ChangeMemberInput input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
        Assert(removeResult, "Remove member failed.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberChanged
        {
            OrganizationAddress = Context.Sender,
            OldMember = input.OldMember,
            NewMember = input.NewMember
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L18-22)
```csharp
    private void AssertIsAuthorizedOrganizationMember(Organization organization, Address member)
    {
        Assert(organization.OrganizationMemberList.Contains(member),
            "Unauthorized member.");
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
