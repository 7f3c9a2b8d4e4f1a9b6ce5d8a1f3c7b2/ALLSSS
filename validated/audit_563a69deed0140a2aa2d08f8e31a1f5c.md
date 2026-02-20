# Audit Report

## Title
Unbounded Proposal Spam Attack on Organizations with Disabled Proposer Authority

## Summary
The Parliament contract allows any address to create unlimited proposals for organizations with `ProposerAuthorityRequired` set to false, including the Emergency Response Organization and Side Chain Lifetime Controller. This enables state bloat attacks and governance disruption without effective rate limiting, proposal caps, or mandatory transaction fees.

## Finding Description

The vulnerability exists in the authorization logic that controls who can create proposals. The `AssertIsAuthorizedProposer` function implements an OR condition that short-circuits when `ProposerAuthorityRequired` is false: [1](#0-0) 

When `!organization.ProposerAuthorityRequired` evaluates to true (meaning the flag is false), the entire assertion passes regardless of whitelist status or parliament membership, allowing any address to create proposals.

The `CreateProposal` method relies solely on this authorization check: [2](#0-1) 

Two critical system organizations are created with this vulnerability:

1. **Emergency Response Organization** - explicitly created with `ProposerAuthorityRequired = false`: [3](#0-2) 

2. **Cross-Chain Side Chain Lifetime Controller** - also created with `ProposerAuthorityRequired = false`: [4](#0-3) 

**Why Existing Protections Fail:**

1. **No Rate Limiting**: The contract state contains no per-address or per-organization tracking for rate limits: [5](#0-4) 

2. **Weak Duplicate Prevention**: While duplicate proposal IDs are rejected, the ID is generated from input hash or token: [6](#0-5) 

Attackers can create unique proposals by varying title, description, or token fields. Length limits are generous: [7](#0-6) 

3. **Transaction Fees Not Enforced**: The `GetMethodFee` implementation returns state that may be null if not configured: [8](#0-7) 

4. **Reactive Cleanup Only**: Proposals can only be cleared after expiration, not preventing spam creation: [9](#0-8) 

## Impact Explanation

**State Bloat (HIGH)**: Each proposal is stored permanently in the Proposals map until manually cleared after expiration. An attacker can create thousands of proposals (limited only by gas and optional fees), each consuming storage with up to 10,710 characters of metadata plus addresses, timestamps, and vote lists. This causes unbounded state growth affecting all nodes.

**Query Performance Degradation (MEDIUM)**: Multiple view methods iterate over proposal IDs without pagination, causing O(n) performance degradation as spam accumulates: [10](#0-9) 

**Governance Disruption (MEDIUM)**: Legitimate proposals become difficult to monitor when buried among spam. Parliament members, indexing services, and automated systems face increased operational costs to filter and process governance data.

The combination of these impacts justifies **HIGH severity** as this affects critical governance infrastructure, has unbounded scaling, and requires minimal attacker resources if fees are unset or low.

## Likelihood Explanation

**Attacker Requirements**: Any address with sufficient balance for gas (and optional transaction fees if configured). No special permissions needed.

**Attack Complexity**: LOW - The attack is straightforward:
1. Obtain the Emergency Response Organization address (publicly known via `GetEmergencyResponseOrganizationAddress`)
2. Call `CreateProposal` repeatedly with varying inputs (title, description, or token)
3. Each call creates a unique proposal ID and stores it in state

**Economic Barriers**: Transaction fees are configurable by governance and may be unset initially, set to zero, or set to amounts insufficient to deter spam. Even with reasonable fees (e.g., 0.01 ELF per proposal), creating 10,000 spam proposals costs only ~100 ELF, which may be economically rational for attackers seeking governance disruption or reputational damage.

**Feasibility**: The vulnerable organizations exist by default in the system initialization, making this attack immediately available on any AElf chain running these contracts.

## Recommendation

Implement multiple layers of protection:

1. **Mandatory Rate Limiting**: Add per-address proposal creation counters with time-based resets in the contract state
2. **Proposal Caps**: Enforce maximum active proposals per organization
3. **Mandatory Transaction Fees**: Ensure `CreateProposal` always charges fees, with reasonable minimum amounts
4. **Pagination Support**: Refactor view methods to support paginated queries
5. **Stricter Duplicate Prevention**: Consider organization-scoped uniqueness checks beyond just proposal ID

For organizations requiring open proposal creation, implement a reputation or staking system where repeat spammers can be penalized.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Obtain the Emergency Response Organization address
2. Loop to create 100+ proposals with varying titles/descriptions
3. Verify all proposals are successfully created and stored
4. Demonstrate query performance degradation on view methods
5. Calculate total state storage consumed

The test would confirm that any address can spam proposals without restriction when `ProposerAuthorityRequired = false`.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L22-34)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        // It is a valid proposer if
        // authority check is disable,
        // or sender is in proposer white list,
        // or sender is one of miners when member proposing allowed.
        Assert(
            !organization.ProposerAuthorityRequired || ValidateAddressInWhiteList(proposer) ||
            (organization.ParliamentMemberProposingAllowed && ValidateParliamentMemberAuthority(proposer)),
            "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L220-223)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L61-66)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L179-186)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L286-347)
```csharp
    public override ProposalIdList GetNotVotedProposals(ProposalIdList input)
    {
        var result = new ProposalIdList();
        foreach (var proposalId in input.ProposalIds)
        {
            var proposal = State.Proposals[proposalId];
            if (proposal == null || !Validate(proposal) || CheckProposalAlreadyVotedBy(proposal, Context.Sender))
                continue;
            result.ProposalIds.Add(proposalId);
        }

        return result;
    }

    public override ProposalIdList GetNotVotedPendingProposals(ProposalIdList input)
    {
        var result = new ProposalIdList();
        var currentParliament = GetCurrentMinerList();
        foreach (var proposalId in input.ProposalIds)
        {
            var proposal = State.Proposals[proposalId];
            if (proposal == null || !Validate(proposal) || CheckProposalAlreadyVotedBy(proposal, Context.Sender))
                continue;
            var organization = State.Organizations[proposal.OrganizationAddress];
            if (organization == null || !IsProposalStillPending(proposal, organization, currentParliament))
                continue;
            result.ProposalIds.Add(proposalId);
        }

        return result;
    }

    public override ProposalIdList GetReleaseThresholdReachedProposals(ProposalIdList input)
    {
        var result = new ProposalIdList();
        foreach (var proposalId in input.ProposalIds)
        {
            var proposal = State.Proposals[proposalId];
            if (proposal == null || !Validate(proposal))
                continue;
            var organization = State.Organizations[proposal.OrganizationAddress];
            if (organization == null || !IsReleaseThresholdReached(proposal, organization))
                continue;
            result.ProposalIds.Add(proposalId);
        }

        return result;
    }
    
    public override ProposalIdList GetAvailableProposals(ProposalIdList input)
    {
        var result = new ProposalIdList();
        foreach (var proposalId in input.ProposalIds)
        {
            var proposal = State.Proposals[proposalId];
            if (proposal == null || !Validate(proposal))
                continue;
            result.ProposalIds.Add(proposalId);
        }

        return result;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L601-611)
```csharp
        State.ParliamentContract.CreateOrganizationBySystemContract.Send(
            new CreateOrganizationBySystemContractInput
            {
                OrganizationCreationInput = new Parliament.CreateOrganizationInput
                {
                    ProposalReleaseThreshold = proposalReleaseThreshold,
                    ProposerAuthorityRequired = false,
                    ParliamentMemberProposingAllowed = true
                },
                OrganizationAddressFeedbackMethod = nameof(SetInitialSideChainLifetimeControllerAddress)
            });
```

**File:** contract/AElf.Contracts.Parliament/ParliamentState.cs (L11-29)
```csharp
public class ParliamentState : ContractState
{
    public MappedState<Address, Organization> Organizations { get; set; }

    public BoolState Initialized { get; set; }

    public SingletonState<Address> DefaultOrganizationAddress { get; set; }

    internal AEDPoSContractContainer.AEDPoSContractReferenceState ConsensusContract { get; set; }
    internal TokenContractContainer.TokenContractReferenceState TokenContract { get; set; }
    internal ElectionContractContainer.ElectionContractReferenceState ElectionContract { get; set; }
    public MappedState<Hash, ProposalInfo> Proposals { get; set; }
    public MappedState<string, MethodFees> TransactionFees { get; set; }

    public SingletonState<ProposerWhiteList> ProposerWhiteList { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }

    public SingletonState<Address> EmergencyResponseOrganizationAddress { get; set; }
}
```

**File:** contract/AElf.Contracts.Parliament/ParliamentConstants.cs (L3-8)
```csharp
public static class ParliamentConstants
{
    public const int MaxLengthForTitle = 255;
    public const int MaxLengthForDescription = 10200;
    public const int MaxLengthForProposalDescriptionUrl = 255;
}
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L34-44)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(ApproveMultiProposals))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };

        return State.TransactionFees[input.Value];
    }
```
