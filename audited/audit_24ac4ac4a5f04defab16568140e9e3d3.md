### Title
Missing Minimum Expiration Time Validation in Association Proposal Creation

### Summary
The Association contract's `CreateNewProposal()` function lacks validation for minimum proposal expiration duration, allowing proposers to create proposals that expire within milliseconds or seconds. This undermines governance integrity by preventing organization members from having reasonable time to review and vote on proposals, despite the system enforcing proposal whitelists and approval thresholds.

### Finding Description

The vulnerability exists in the proposal validation logic within the `Validate(ProposalInfo proposal)` helper method: [1](#0-0) 

The validation only checks that `ExpiredTime` is not null and that it is greater than the current block time. There is no enforcement of a minimum duration between `CurrentBlockTime` and `ExpiredTime`.

This validation is called during proposal creation: [2](#0-1) 

The same insufficient validation pattern exists in Parliament and Referendum contracts: [3](#0-2) [4](#0-3) 

Test evidence confirms that proposals with expiration times as short as 5 milliseconds are accepted as valid: [5](#0-4) 

### Impact Explanation

This vulnerability enables governance manipulation through artificially short proposal lifetimes:

1. **Governance Disruption**: Authorized proposers can create proposals that expire before organization members have meaningful opportunity to review and vote. With blocks produced every 4 seconds, a proposal expiring in 1 second would be invalid before the next block is mined. [6](#0-5) 

2. **Inconsistent Design**: This contrasts with the Genesis contract which enforces minimum expiration periods of 259,200 seconds (3 days) for contract proposals and 900 seconds (15 minutes) for code checks, demonstrating that the system designers recognize the need for reasonable governance windows: [7](#0-6) 

3. **Who is Affected**: All organization members lose the ability to meaningfully participate in governance when proposals expire too quickly.

4. **Severity Justification**: Medium severity - while this doesn't enable direct fund theft, it fundamentally undermines the governance process which is a critical invariant for the Authorization & Governance subsystem.

### Likelihood Explanation

**Attacker Capabilities**: Requires membership in the organization's ProposerWhiteList, which is the legitimate access control for proposal creation. [8](#0-7) 

**Attack Complexity**: Trivial - simply call `CreateProposal` with `ExpiredTime` set to `CurrentBlockTime + Duration.FromSeconds(1)` or even milliseconds.

**Feasibility**: Highly feasible - no additional preconditions beyond standard proposer authorization.

**Detection/Operational Constraints**: Difficult to detect until members notice they cannot vote due to expired proposals. The `ClearProposal` function allows cleanup but doesn't prevent the initial disruption: [9](#0-8) 

**Economic Rationality**: Low cost (only gas fees) with high impact on governance legitimacy.

### Recommendation

Implement minimum expiration time validation in the `Validate(ProposalInfo proposal)` method for Association, Parliament, and Referendum contracts:

```csharp
private bool Validate(ProposalInfo proposal)
{
    const int MinimumProposalLifetimeSeconds = 86400; // 1 day minimum
    
    if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    if (proposal.ExpiredTime == null)
        return false;
        
    var minimumExpiredTime = Context.CurrentBlockTime.AddSeconds(MinimumProposalLifetimeSeconds);
    return proposal.ExpiredTime >= minimumExpiredTime;
}
```

Add configuration parameters similar to Genesis contract to allow governance-controlled adjustment of minimum expiration periods. Add test cases to verify proposals with insufficient expiration time are rejected.

### Proof of Concept

**Required Initial State**:
- Association organization created with member list and proposer whitelist
- Test account is member of proposer whitelist

**Transaction Steps**:
1. Call `CreateProposal` with valid parameters but `ExpiredTime = CurrentBlockTime.AddSeconds(1)`
2. Proposal is created successfully (passes validation)
3. Wait for next block (4 seconds later based on MiningInterval)
4. Attempt to vote on proposal
5. Voting fails because proposal is now expired

**Expected Result**: Proposal should be rejected at creation time due to insufficient expiration duration.

**Actual Result**: Proposal is created successfully and expires before meaningful governance participation is possible, violating the governance integrity invariant.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L83-90)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
            !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
            return false;

        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L145-173)
```csharp
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L177-180)
```csharp
    private bool CheckProposalNotExpired(ProposalInfo proposal)
    {
        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L104-113)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L376-384)
```csharp
        //"Expired proposal."
        {
            createProposalInput.ExpiredTime = blockTime.AddMilliseconds(5);
            BlockTimeProvider.SetBlockTime(TimestampHelper.GetUtcNow().AddSeconds(10));

            var transactionResult =
                await associationContractStub.CreateProposal.SendWithExceptionAsync(createProposalInput);
            transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        }
```

**File:** src/AElf.Launcher/appsettings.json (L26-30)
```json
  "Consensus": {
    "InitialMinerList": [],
    "MiningInterval": 4000,
    "StartTimestamp": 0,
    "PeriodSeconds": 604800,
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L1-11)
```csharp
namespace AElf.Contracts.Genesis;

public partial class BasicContractZero
{
    public const int ContractProposalExpirationTimePeriod = 259200; // 60 * 60 * 72
    public const int DefaultCodeCheckProposalExpirationTimePeriod = 900; // 60 * 15
    private const int MinimalApprovalThreshold = 6667;
    private const int MaximalAbstentionThreshold = 1000;
    private const int MaximalRejectionThreshold = 1000;
    private const int MinimalVoteThresholdThreshold = 8000;
}
```

**File:** contract/AElf.Contracts.Association/Association.cs (L107-112)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L282-289)
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
