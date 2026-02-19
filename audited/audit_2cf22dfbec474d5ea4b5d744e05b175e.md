### Title
Referendum Proposals Create Unmitigated State Bloat Due to Lack of Cleanup Incentive

### Summary
The Referendum contract allows whitelisted proposers to create unlimited proposals with only transaction fee costs. While `ClearProposal()` exists to remove expired proposals, it requires manual invocation with no economic incentive, creating a practical state bloat attack vector. An attacker can spam proposals that never reach voting thresholds, and these proposals will remain in state indefinitely unless someone manually clears each one.

### Finding Description

**Root Cause:**

The proposal creation flow has three critical weaknesses:

1. **No Creation Deposit**: The `CreateProposal` method only checks whitelist authorization but requires no deposit or stake. [1](#0-0) 

2. **Indefinite State Storage**: Proposals are stored permanently in the `State.Proposals` mapping when created. [2](#0-1)  The proposal data includes method names, addresses, parameters, timestamps, title, description, and URL - consuming significant state space per proposal.

3. **No Cleanup Incentive**: The `ClearProposal` method allows anyone to remove expired proposals, but provides no economic reward for doing so. [3](#0-2)  This creates a "public good problem" where no rational actor pays gas to clean up someone else's spam.

**Execution Path:**

1. Attacker creates a referendum organization with themselves on the `ProposerWhiteList`. [4](#0-3) 

2. The whitelist check only verifies the proposer is authorized, with no additional restrictions. [5](#0-4) 

3. Attacker repeatedly calls `CreateProposal` with unique token values to generate different proposal IDs, long expiration times (e.g., 1 year), and content that won't reach approval threshold. [6](#0-5) 

4. Input validation only checks title/description/URL length, not proposal creation rate or cost. [7](#0-6) 

5. Proposals remain in state until either `Release()` is called (requires threshold - won't happen for spam proposals) or `ClearProposal()` is manually invoked. [8](#0-7) 

**Why Protections Fail:**

- `ClearProposal` exists but depends entirely on altruistic manual cleanup with no economic incentive
- No automatic garbage collection of expired proposals
- No rate limiting on proposal creation per proposer  
- No proposal deposit mechanism that gets slashed for failed/expired proposals
- Method fees (if configured via `SetMethodFee`) are minimal compared to state bloat damage and don't prevent the attack [9](#0-8) 

### Impact Explanation

**Concrete Harm:**

- State bloat increases storage requirements for all nodes running the blockchain
- Each proposal stores substantial data including addresses, strings (up to 10,200 characters for description), parameters, and timestamps [10](#0-9) 
- An attacker with minimal cost can create thousands of proposals
- State database grows unbounded as expired proposals accumulate
- Long-term degradation of chain performance and increased storage costs for all node operators
- Practically permanent bloat since no incentive exists for cleanup

**Affected Parties:**

- All node operators bear increased storage costs
- Network performance degrades with bloated state
- Cleanup (if attempted) requires coordination and gas expenditure with no compensation

**Severity Justification:**

Medium severity because:
- Does not directly steal funds or compromise consensus
- Requires whitelisted access (though attacker can whitelist themselves via own organization)
- Creates operational DoS through resource exhaustion
- Impact accumulates over time but is reversible in theory (not practice)

### Likelihood Explanation

**Attacker Capabilities:**

- Must be on `ProposerWhiteList` OR create own organization
- Creating organization requires only calling `CreateOrganization` with self in whitelist [4](#0-3) 
- Organization validation only checks that whitelist is non-empty, not who is on it [11](#0-10) 
- No significant barriers to entry

**Attack Complexity:**

- Low complexity: Simple repeated calls to `CreateProposal`
- Cost: Only transaction fees (unless method fee is configured, which is optional)
- Can automate proposal creation easily using loops
- No rate limits, quotas, or deposit requirements
- Proposals can have unique IDs by varying the `token` parameter [6](#0-5) 

**Feasibility Conditions:**

- All steps use standard public methods accessible to any user
- No special privileges beyond whitelist (self-granted via own organization)
- Attack sustainable over time with minimal ongoing cost
- Cleanup is impractical at scale (requires one transaction per proposal)

**Probability:**

Medium likelihood - while attacker needs whitelist access, creating a self-controlled organization is trivial, making this attack accessible to any user willing to pay modest transaction fees.

### Recommendation

**Immediate Mitigations:**

1. **Implement Proposal Creation Deposit**: Require a refundable deposit when creating proposals. Store deposit information in state alongside the proposal. The deposit should be returned on successful `Release()` and slashed on expiration.

2. **Incentivize Cleanup**: Modify `ClearProposal` to reward the caller with a portion of the slashed deposit (e.g., 50% to cleaner, 50% burned). This creates economic incentive for users to clean up expired proposals.

3. **Add Rate Limiting**: Implement per-proposer rate limits (e.g., maximum 10 proposals per 24 hours). Track proposal counts per address in state and reset windows after the time period expires.

4. **Add Proposal Count Limits**: Limit the number of active proposals per organization to prevent unbounded growth.

**Invariant Checks:**

- Assert deposit is paid before proposal creation succeeds
- Assert deposit is either returned (on Release) or slashed (on expiration cleanup)
- Assert rate limits are not exceeded per proposer
- Add monitoring for proposal count growth rates per organization

**Test Cases:**

- Test proposal creation requires deposit payment
- Test deposit is returned on successful release
- Test deposit is slashed and reward paid on expiration cleanup  
- Test rate limit blocks excessive proposal creation
- Test cleanup economic incentive attracts participants
- Test state bloat attack is prevented by deposit + rate limit combination

### Proof of Concept

**Required Initial State:**
- Attacker has ELF tokens for transaction fees
- Token contract and Referendum contract are deployed

**Attack Steps:**

1. **Create attacker-controlled organization**: Call `CreateOrganization` with attacker's address in `ProposerWhiteList` and impossibly high voting thresholds to ensure proposals never pass.

2. **Spam proposals**: In a loop (e.g., 1000 iterations):
   - Call `CreateProposal` with unique `token` parameter for each proposal
   - Set `ExpiredTime` to 1 year in the future
   - Set `Title` to "Spam {i}" and `Description` to maximum allowed length (10,200 characters)
   - Set organization threshold high enough that proposals cannot pass

3. **Verify state bloat**: Query `GetProposal` for all created proposal IDs to confirm they exist in state.

4. **Fast-forward time**: Advance blockchain time by 2 years to ensure all proposals expire.

5. **Verify no automatic cleanup**: Query proposals again - all 1000 still exist in state after expiration.

6. **Demonstrate cleanup burden**: To remove proposals, must call `ClearProposal` 1000 times, each costing gas, with no reward for doing so.

**Expected vs Actual Result:**

- **Expected**: Either (1) proposal creation has meaningful cost/deposit to deter spam, or (2) expired proposals are automatically cleaned up, or (3) economic incentive exists for manual cleanup
- **Actual**: 1000 proposals remain in state indefinitely after expiration, requiring expensive manual cleanup with no incentive. State bloat persists until someone altruistically pays to clear each proposal individually.

**Success Condition:**

Attack succeeds when:
1. Attacker creates many proposals at low cost (only transaction fees)
2. Proposals remain in state past expiration indefinitely
3. No cleanup occurs due to lack of economic incentive
4. State continues growing with each attack iteration

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L12-40)
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
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-59)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L154-161)
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L154-157)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L159-187)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ToAddress = input.ToAddress,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            OrganizationAddress = input.OrganizationAddress,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L189-198)
```csharp
    private void CheckCreateProposalInput(CreateProposalInput input)
    {
        // Check the length of title
        Assert(input.Title.Length <= ReferendumConstants.MaxLengthForTitle, "Title is too long.");
        // Check the length of description
        Assert(input.Description.Length <= ReferendumConstants.MaxLengthForDescription, "Description is too long.");
        // Check the length of description url
        Assert(input.ProposalDescriptionUrl.Length <= ReferendumConstants.MaxLengthForProposalDescriptionUrl,
            "Description url is too long.");
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

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L10-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Referendum/ReferendumConstants.cs (L4-7)
```csharp
{
    public const int MaxLengthForTitle = 255;
    public const int MaxLengthForDescription = 10200;
    public const int MaxLengthForProposalDescriptionUrl = 255;
```
