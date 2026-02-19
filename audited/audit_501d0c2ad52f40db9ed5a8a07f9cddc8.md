# Audit Report

## Title
Association Organization Permanent Deadlock via 100% Vote Threshold Requirement

## Summary
The Association contract's validation logic permits creating organizations where `MinimalVoteThreshold` equals `organizationMemberCount`, requiring unanimous participation for all proposals. When one member becomes unavailable, the organization enters permanent deadlock with no recovery mechanism, rendering any controlled assets or permissions permanently inaccessible.

## Finding Description

The vulnerability exists in the organization validation logic that allows `MinimalVoteThreshold` to equal the total member count. [1](#0-0) 

This configuration requires unanimous participation for proposal approval. The vote counting logic enforces this requirement by checking total vote count against the threshold. [2](#0-1) 

All organization modification methods retrieve the organization using `Context.Sender` as the key, meaning they can only be invoked by the organization address itself. [3](#0-2) [4](#0-3) [5](#0-4) 

The organization can only act through released proposals executed via virtual addresses. [6](#0-5) 

**Deadlock Scenario:**
1. Organization created with 3 members and `MinimalVoteThreshold = 3`
2. One member loses private key, becomes malicious, or is otherwise unavailable
3. Maximum achievable votes = 2 (from remaining members)
4. No proposal can reach threshold of 3
5. Cannot remove unavailable member (requires proposal passage)
6. Cannot lower threshold (requires proposal passage)
7. Cannot add new members (requires proposal passage)
8. Organization permanently locked with no recovery path

All modification operations validate the organization after changes, enforcing these constraints. [7](#0-6) [8](#0-7) [9](#0-8) 

## Impact Explanation

**Permanent Asset Loss:**
- Any tokens held by the organization address become permanently locked
- Permissions granted to the organization become unusable
- Contract authorizations assigned to the organization cannot be revoked or modified

**Griefing Attack Vector:**
- Malicious actor creates organization with `MinimalVoteThreshold = memberCount`
- Other members deposit funds or assign governance permissions to the organization
- Malicious actor stops participating, holding assets hostage
- Other members have no recourse to recover funds or modify organization

**Systemic Risk:**
- Affects all user-created Association organizations using this configuration
- No warning exists during organization creation about this risk
- Configuration appears reasonable for organizations wanting strong consensus
- Particularly severe for financial organizations controlling significant token amounts

## Likelihood Explanation

**High Likelihood:**

1. **Configuration Appears Reasonable:** Requiring unanimous consent seems like a valid governance model for high-stakes decisions

2. **No Warnings:** The contract accepts this configuration without any indication that it creates unrecoverable deadlock risk [10](#0-9) 

3. **Common Occurrence:** Member unavailability is frequent in practice:
   - Lost private keys
   - Death or long-term absence
   - Malicious actors
   - Disputes between members

4. **Zero Attack Cost:** For griefing attacks, the malicious member simply stops participating—no additional resources required

5. **Public Method Access:** Any user can create organizations with this configuration via the public `CreateOrganization` method [11](#0-10) 

## Recommendation

Implement one or more of the following mitigations:

1. **Strict Upper Bound:** Modify validation to reject configurations where `MinimalVoteThreshold == organizationMemberCount`:
   ```csharp
   return proposalReleaseThreshold.MinimalVoteThreshold < organizationMemberCount &&
   ```

2. **Warning Threshold:** Add a maximum safe threshold (e.g., 80% of members) and require special acknowledgment for higher values

3. **Emergency Recovery:** Implement a time-locked recovery mechanism where if no proposals pass for an extended period, the threshold automatically decreases

4. **Founder Override:** Allow the organization creator to reduce the threshold after a long inactivity period, with adequate safeguards

The minimal fix is option 1, changing line 72 in `Association_Helper.cs` from `<=` to `<`.

## Proof of Concept

```csharp
[Fact]
public async Task Organization_Deadlock_With_100Percent_Threshold()
{
    // Setup: Create organization with 3 members and MinimalVoteThreshold = 3 (100%)
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 3,
            MinimalVoteThreshold = 3,  // Requires 100% participation
            MaximalAbstentionThreshold = 0,
            MaximalRejectionThreshold = 0
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { Reviewer1 } }
    };
    
    var orgAddress = await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    
    // Create proposal to remove Reviewer3
    var proposalInput = new CreateProposalInput
    {
        OrganizationAddress = orgAddress.Output,
        ContractMethodName = nameof(AssociationContractStub.RemoveMember),
        ToAddress = AssociationContractAddress,
        Params = Reviewer3.ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    };
    
    var proposalId = await AssociationContractStub.CreateProposal.SendAsync(proposalInput);
    
    // Only Reviewer1 and Reviewer2 vote (Reviewer3 unavailable)
    await AssociationContractStub.Approve.SendAsync(proposalId.Output);
    await AssociationContractStubReviewer2.Approve.SendAsync(proposalId.Output);
    
    // Attempt to release - should fail due to insufficient votes
    var releaseResult = await AssociationContractStub.Release.SendWithExceptionAsync(proposalId.Output);
    
    // Assert: Proposal cannot be released, organization is permanently deadlocked
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved");
    
    // Organization is now permanently locked with no recovery mechanism
}
```

## Notes

While system contracts may intentionally use this configuration with contract-based members that are always available, exposing this capability to user-created organizations with human members creates an unacceptable risk. The validation logic should distinguish between system contract organizations and user organizations, or universally prevent 100% threshold requirements to protect against both accidental misconfiguration and malicious griefing attacks.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-58)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-72)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
```

**File:** contract/AElf.Contracts.Association/Association.cs (L69-94)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            ProposerWhiteList = input.ProposerWhiteList,
            OrganizationMemberList = input.OrganizationMemberList,
            OrganizationHash = organizationHash,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization.");
        if (State.Organizations[organizationAddress] == null)
        {
            State.Organizations[organizationAddress] = organization;
            Context.Fire(new OrganizationCreated
            {
                OrganizationAddress = organizationAddress
            });
        }

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L205-205)
```csharp
        var organization = State.Organizations[Context.Sender];
```

**File:** contract/AElf.Contracts.Association/Association.cs (L208-208)
```csharp
        Assert(Validate(organization), "Invalid organization.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L235-235)
```csharp
        var organization = State.Organizations[Context.Sender];
```

**File:** contract/AElf.Contracts.Association/Association.cs (L238-238)
```csharp
        Assert(Validate(organization), "Invalid organization.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L268-268)
```csharp
        var organization = State.Organizations[Context.Sender];
```

**File:** contract/AElf.Contracts.Association/Association.cs (L272-272)
```csharp
        Assert(Validate(organization), "Invalid organization.");
```
