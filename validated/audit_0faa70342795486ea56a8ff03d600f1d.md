# Audit Report

## Title
Unbounded Proposal Spam Attack on Organizations with Disabled Proposer Authority

## Summary
The Parliament contract allows any address to create unlimited proposals for organizations with `ProposerAuthorityRequired` set to false, including the Emergency Response Organization and Side Chain Lifetime Controller. This enables state bloat attacks and governance disruption without effective rate limiting, proposal caps, or mandatory transaction fees.

## Finding Description

The vulnerability exists in the authorization logic that controls who can create proposals. The `AssertIsAuthorizedProposer` function implements an OR condition that short-circuits when `ProposerAuthorityRequired` is false: [1](#0-0) 

When `!organization.ProposerAuthorityRequired` evaluates to true (i.e., when the flag is false), the entire assertion passes regardless of whitelist status or parliament membership, allowing **any address** to create proposals.

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

**Economic Barriers**: Transaction fees are configurable by governance and may be:
- Unset initially (GetMethodFee returns null)
- Set to zero
- Set to amounts insufficient to deter spam

Even with reasonable fees (e.g., 0.01 ELF per proposal), creating 10,000 spam proposals costs only ~100 ELF, which may be economically rational for attackers seeking governance disruption or reputational damage.

**Feasibility**: The vulnerable organizations exist by default in the system initialization, making this attack immediately available on any AElf chain running these contracts.

## Recommendation

Implement comprehensive spam protection mechanisms:

1. **Add Rate Limiting**: Introduce per-address and per-organization rate limits with cooldown periods in the contract state.

2. **Implement Proposal Caps**: Set maximum active proposals per organization and per proposer address.

3. **Enforce Mandatory Fees**: Require non-zero transaction fees for CreateProposal operations, with governance-controlled minimum thresholds.

4. **Add Proposer Deposits**: Require proposers to lock tokens that are returned only if proposals aren't flagged as spam by governance.

5. **Strengthen Authorization**: For system-critical organizations like Emergency Response and Side Chain Controller, consider requiring at least parliament membership even when `ProposerAuthorityRequired` is false.

Example fix for rate limiting in Parliament_Helper.cs:
```csharp
private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
{
    var organization = State.Organizations[organizationAddress];
    Assert(organization != null, "No registered organization.");
    
    // Add rate limit check
    var lastProposalTime = State.ProposerLastProposalTime[proposer][organizationAddress];
    Assert(Context.CurrentBlockTime >= lastProposalTime.AddSeconds(MinProposalInterval), 
        "Rate limit: proposal creation too frequent.");
    
    Assert(
        !organization.ProposerAuthorityRequired || ValidateAddressInWhiteList(proposer) ||
        (organization.ParliamentMemberProposingAllowed && ValidateParliamentMemberAuthority(proposer)),
        "Unauthorized to propose.");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task UnboundedProposalSpamAttack_StateBlot()
{
    // Setup: Get Emergency Response Organization address
    await ParliamentContractStub.CreateEmergencyResponseOrganization.SendAsync(new Empty());
    var emergencyOrg = await ParliamentContractStub.GetEmergencyResponseOrganizationAddress.CallAsync(new Empty());
    
    // Attack: Any address can spam proposals
    var attackerStub = GetParliamentContractTester(TesterKeyPair); // Non-privileged address
    
    // Create 100 spam proposals (in practice, thousands could be created)
    for (int i = 0; i < 100; i++)
    {
        var result = await attackerStub.CreateProposal.SendAsync(new CreateProposalInput
        {
            OrganizationAddress = emergencyOrg,
            ToAddress = TokenContractAddress,
            ContractMethodName = nameof(TokenContractStub.Transfer),
            Params = new Empty().ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            Title = $"Spam Proposal {i}", // Varying title creates unique proposal ID
            Description = "This is spam proposal to bloat state"
        });
        
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    }
    
    // Verify: All spam proposals are stored in state
    // State has grown by 100 proposals with no authorization checks or rate limits
    // Each proposal consumes storage space indefinitely until manually cleared after expiration
}
```

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L220-253)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
    }

    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            ToAddress = input.ToAddress,
            OrganizationAddress = input.OrganizationAddress,
            ProposalId = proposalId,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        State.Proposals[proposalId] = proposal;
        Context.Fire(new ProposalCreated
        {
            ProposalId = proposalId, 
            OrganizationAddress = input.OrganizationAddress,
            Title = input.Title,
            Description = input.Description
        });
        return proposalId;
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L286-333)
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
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L604-611)
```csharp
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

**File:** contract/AElf.Contracts.Parliament/ParliamentConstants.cs (L1-8)
```csharp
namespace AElf.Contracts.Parliament;

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
