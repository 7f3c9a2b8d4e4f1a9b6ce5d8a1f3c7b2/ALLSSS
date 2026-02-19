# Audit Report

## Title
Self-Modification Deadlock in Referendum Contract Due to Insufficient Threshold and Whitelist Validation

## Summary
The Referendum contract's `ChangeOrganizationThreshold` and `ChangeOrganizationProposerWhiteList` functions lack critical validation checks that could allow organizations to set impossible thresholds or inaccessible whitelists, creating an irrecoverable governance deadlock with no recovery mechanism.

## Finding Description

The Referendum contract allows organizations to modify their own governance parameters through proposals. The `ChangeOrganizationThreshold` function requires `Context.Sender` to equal the organization address [1](#0-0) , and similarly for `ChangeOrganizationProposerWhiteList` [2](#0-1) . These functions are invoked through the `Release` method which uses `SendVirtualInlineBySystemContract` to set the sender to the organization's virtual address [3](#0-2) .

The critical vulnerability lies in the insufficient validation performed by the `Validate` function [4](#0-3) . This validation only checks basic constraints (non-empty whitelist, threshold relationships, non-negative values) but does NOT verify:

1. That `MinimalVoteThreshold` or `MinimalApprovalThreshold` are achievable given actual token supply
2. That whitelist addresses are valid or accessible
3. That `MaximalRejectionThreshold` allows practical governance (the threshold check uses strict inequality)

The proposal release logic enforces a strict inequality check for rejections [5](#0-4) , where setting `MaximalRejectionThreshold = 0` means any proposal with even one rejection vote will fail.

In contrast, the Association contract has superior validation that prevents similar deadlocks by validating thresholds against `organizationMemberCount` [6](#0-5) . The Referendum contract lacks equivalent checks against token supply or voter participation.

**Attack Scenario:**
1. Proposer creates proposal targeting `ChangeOrganizationThreshold` with extreme values (e.g., `MinimalVoteThreshold = 10^18` when token supply is much lower)
2. Proposal gets approved under current reasonable thresholds
3. Proposal is released, updating organization parameters
4. Organization is now permanently deadlocked - no future proposals can meet the impossible threshold
5. No recovery mechanism exists as only the organization itself can modify these parameters

## Impact Explanation

**Severity: HIGH**

Once an organization sets problematic parameters, three deadlock scenarios emerge:

**Scenario 1 - Impossible Vote Threshold:** Setting `MinimalVoteThreshold` to a value exceeding total token supply means no proposal can ever accumulate sufficient votes to be released. The organization cannot create corrective proposals because they cannot meet the approval threshold.

**Scenario 2 - Zero Rejection Threshold:** Setting `MaximalRejectionThreshold = 0` means any proposal with ≥1 rejection vote fails the release check. In referendum-based democratic governance, achieving zero dissent is practically impossible. Recovery proposals will inevitably receive at least one rejection, perpetuating the deadlock.

**Scenario 3 - Inaccessible Whitelist:** Setting the proposer whitelist to addresses with lost keys or inaccessible contract addresses prevents anyone from creating proposals, including corrective ones. The `AssertIsAuthorizedProposer` check will permanently block proposal creation [7](#0-6) .

**Affected Parties:** Any Referendum organization that sets invalid thresholds becomes permanently non-functional. All governance decisions requiring that organization are blocked indefinitely, with no administrative override or recovery path available.

The only write operations to organization state are in `CreateOrganization`, `ChangeOrganizationThreshold`, and `ChangeOrganizationProposerWhiteList` - there is no admin recovery function [8](#0-7) .

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

**Attacker Capabilities:**
- Requires only normal proposer rights (being in the whitelist)
- No special privileges or system contract access needed
- Can be executed accidentally through misconfiguration or intentionally by malicious actors

**Attack Complexity: LOW**
1. Create proposal calling `ChangeOrganizationThreshold` with extreme/invalid values
2. Get proposal approved under current (still reasonable) thresholds
3. Release proposal - organization immediately enters deadlock state
4. No validation prevents setting problematic values during the state change

**Feasibility Conditions:**
- Proposal creation requires whitelist membership (standard operation)
- Proposal approval requires meeting current thresholds (achievable before attack)
- The validation function does not check against token supply or practical governance constraints
- Once parameters are set, deadlock is immediate and permanent

**Detection Difficulty:** The issue is difficult to prevent proactively. No warnings are provided, and once parameters are set, the deadlock is irreversible. This can occur through legitimate governance operations gone wrong or deliberate sabotage.

## Recommendation

Implement comprehensive validation similar to the Association contract's approach. The `Validate` function should be enhanced to:

1. **Query token supply and validate thresholds are achievable:**
   - Check that `MinimalVoteThreshold` does not exceed reasonable proportion of total token supply
   - Validate that threshold combinations allow practical governance

2. **Validate whitelist address accessibility:**
   - Ensure whitelist contains at least one valid, accessible address
   - Consider checking addresses are not burn addresses or system contracts without proper owners

3. **Add threshold compatibility checks:**
   - Ensure `MaximalRejectionThreshold` is not set to values that make governance impractical (e.g., > 0)
   - Validate that `MaximalAbstentionThreshold + MinimalApprovalThreshold` allows achievable quorum
   - Verify `MaximalRejectionThreshold + MinimalApprovalThreshold` is feasible

4. **Consider implementing emergency recovery mechanism:**
   - Allow a trusted system contract or multi-sig to reset deadlocked organizations
   - Implement time-delayed recovery that can be cancelled by successful proposals

The validation logic should mirror the Association contract's comprehensive checks adapted for token-based voting rather than member-based voting.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```csharp
// 1. Create Referendum organization with reasonable initial thresholds
var orgAddress = ReferendumContract.CreateOrganization(new CreateOrganizationInput {
    TokenSymbol = "ELF",
    ProposalReleaseThreshold = new ProposalReleaseThreshold {
        MinimalVoteThreshold = 1000,
        MinimalApprovalThreshold = 600,
        MaximalRejectionThreshold = 200,
        MaximalAbstentionThreshold = 200
    },
    ProposerWhiteList = new ProposerWhiteList { Proposers = { proposerAddress } }
});

// 2. Create malicious proposal to set impossible threshold
var proposalId = ReferendumContract.CreateProposal(new CreateProposalInput {
    OrganizationAddress = orgAddress,
    ContractMethodName = "ChangeOrganizationThreshold",
    ToAddress = ReferendumContract.Address,
    Params = new ProposalReleaseThreshold {
        MinimalVoteThreshold = 1_000_000_000_000, // Impossible to achieve
        MinimalApprovalThreshold = 600_000_000_000,
        MaximalRejectionThreshold = 0, // Any rejection fails
        MaximalAbstentionThreshold = 0
    }.ToByteString()
});

// 3. Approve with sufficient votes under current thresholds
ReferendumContract.Approve(proposalId); // Gets 1000 votes

// 4. Release proposal - organization is now deadlocked
ReferendumContract.Release(proposalId);

// 5. Attempt recovery proposal - will fail due to impossible thresholds
var recoveryProposalId = ReferendumContract.CreateProposal(recoveryInput);
// Cannot accumulate 1_000_000_000_000 votes - permanent deadlock
```

The test demonstrates that once the malicious proposal is released, the organization cannot pass any future proposals, including corrective ones, because the new thresholds are mathematically impossible to achieve given the token supply constraints.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L12-152)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            TokenSymbol = input.TokenSymbol,
            OrganizationHash = organizationHash,
            ProposerWhiteList = input.ProposerWhiteList,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization data.");

        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;

        State.Organizations[organizationAddress] = organization;
        Context.Fire(new OrganizationCreated
        {
            OrganizationAddress = organizationAddress
        });

        return organizationAddress;
    }

    public override Address CreateOrganizationBySystemContract(CreateOrganizationBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to create organization.");
        var organizationAddress = CreateOrganization(input.OrganizationCreationInput);
        if (!string.IsNullOrEmpty(input.OrganizationAddressFeedbackMethod))
            Context.SendInline(Context.Sender, input.OrganizationAddressFeedbackMethod, organizationAddress);

        return organizationAddress;
    }

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

    public override Empty Approve(Hash input)
    {
        var proposal = GetValidProposal(input);
        var organization = State.Organizations[proposal.OrganizationAddress];
        var allowance = GetAllowance(Context.Sender, organization.TokenSymbol, input);

        proposal.ApprovalCount = proposal.ApprovalCount.Add(allowance);
        State.Proposals[input] = proposal;
        var referendumReceiptCreated = LockToken(organization.TokenSymbol, allowance, input, Context.Sender,
            proposal.OrganizationAddress);
        referendumReceiptCreated.ReceiptType = nameof(Approve);
        Context.Fire(referendumReceiptCreated);
        return new Empty();
    }

    public override Empty Reject(Hash input)
    {
        var proposal = GetValidProposal(input);
        var organization = State.Organizations[proposal.OrganizationAddress];
        var allowance = GetAllowance(Context.Sender, organization.TokenSymbol, input);

        proposal.RejectionCount = proposal.RejectionCount.Add(allowance);
        State.Proposals[input] = proposal;
        var referendumReceiptCreated = LockToken(organization.TokenSymbol, allowance, input, Context.Sender,
            proposal.OrganizationAddress);
        referendumReceiptCreated.ReceiptType = nameof(Reject);
        Context.Fire(referendumReceiptCreated);
        return new Empty();
    }

    public override Empty Abstain(Hash input)
    {
        var proposal = GetValidProposal(input);
        var organization = State.Organizations[proposal.OrganizationAddress];
        var allowance = GetAllowance(Context.Sender, organization.TokenSymbol, input);

        proposal.AbstentionCount = proposal.AbstentionCount.Add(allowance);
        State.Proposals[input] = proposal;
        var referendumReceiptCreated = LockToken(organization.TokenSymbol, allowance, input, Context.Sender,
            proposal.OrganizationAddress);
        referendumReceiptCreated.ReceiptType = nameof(Abstain);
        Context.Fire(referendumReceiptCreated);
        return new Empty();
    }

    public override Empty ReclaimVoteToken(Hash input)
    {
        var proposal = State.Proposals[input];
        Assert(proposal == null ||
               Context.CurrentBlockTime >= proposal.ExpiredTime, "Unable to reclaim at this time.");
        UnlockToken(input, Context.Sender);
        return new Empty();
    }

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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L163-177)
```csharp
    public override Empty Release(Hash input)
    {
        var proposal = GetValidProposal(input);
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
        var organization = State.Organizations[proposal.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposal.ToAddress,
            proposal.ContractMethodName, proposal.Params);

        Context.Fire(new ProposalReleased { ProposalId = input });
        State.Proposals.Remove(input);

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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L200-205)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "Organization not found.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
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
