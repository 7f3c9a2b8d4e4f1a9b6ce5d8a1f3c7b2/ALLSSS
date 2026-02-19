### Title
Approved Proposals Can Be Cleared Before Execution Due to Missing Release Threshold Check

### Summary
The `ClearProposal` function in Parliament, Association, and Referendum contracts only validates that a proposal has expired, but does not check if the proposal has already reached its release threshold. This allows anyone to permanently delete fully approved proposals that are ready for execution, simply because they expired before the proposer called `Release`, causing loss of governance control and wasted voting effort.

### Finding Description

The `ClearProposal` function in the Parliament contract (and identically in Association and Referendum contracts) contains a critical logic error. The function only checks two conditions before allowing proposal deletion: [1](#0-0) 

The function verifies that:
1. The proposal exists
2. Current block time >= proposal's ExpiredTime

However, it completely ignores whether the proposal has reached its release threshold. The `IsReleaseThresholdReached` function exists and is used in the `Release` method to validate if a proposal has sufficient approvals: [2](#0-1) 

The `IsReleaseThresholdReached` function performs comprehensive checks for approval counts, rejection thresholds, and abstention thresholds: [3](#0-2) 

The `GetProposal` view function correctly calculates and exposes the `ToBeReleased` status indicating if a proposal has reached its release threshold: [4](#0-3) 

**Execution Path:**
1. Proposer creates a proposal with ExpiredTime (typically 2 days)
2. Parliament members vote and the proposal reaches release threshold (ToBeReleased = true)
3. Proposer doesn't call `Release` before expiration (due to being busy, network delays, waiting for more votes, or key compromise)
4. Anyone calls `ClearProposal` after expiration
5. The approved proposal is permanently deleted from state without execution

The same vulnerability exists in Association and Referendum contracts: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Governance Impact:**
- Approved proposals containing critical system upgrades, parameter changes, or fund transfers can be permanently deleted
- The entire governance process (proposal creation, voting period, reaching consensus) becomes wasted effort
- No recovery mechanism exists - the proposal must be recreated and voted on again from scratch
- This breaks the fundamental governance invariant that approved proposals should be executable

**Operational Impact:**
- Creates a griefing attack vector where malicious actors can deliberately prevent approved proposals from executing
- Proposers who are temporarily inactive or dealing with network issues lose their approved proposals
- Time-sensitive governance decisions (emergency responses, urgent parameter adjustments) can be blocked

**Affected Parties:**
- All governance participants who spent time and resources voting on proposals
- The protocol itself, which loses the ability to execute approved changes
- Users depending on governance outcomes (e.g., parameter updates, fund allocations)

**Severity Justification:**
Medium severity due to:
- High impact on governance functionality
- Moderate likelihood based on realistic operational scenarios
- Affects all three primary governance contracts
- No special privileges required to exploit (anyone can call `ClearProposal`)

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required - `ClearProposal` is publicly callable by anyone
- Only needs to wait for proposal expiration
- Can monitor blockchain for proposals nearing expiration with high approval counts

**Attack Complexity:**
- Low complexity: single transaction call to `ClearProposal` after expiration
- No complex state manipulation required
- No economic cost beyond gas fees

**Feasible Preconditions:**
Proposals are created with limited expiration windows (typically 2 days based on test code): [7](#0-6) 

**Realistic Scenarios:**
1. **Proposer Unavailability:** Proposer monitoring intermittently and missing the narrow release window between approval and expiration
2. **Network Congestion:** High transaction volume delaying the `Release` transaction past expiration
3. **Strategic Waiting:** Proposer waiting for additional votes to strengthen consensus, accidentally exceeding expiration
4. **Key Management Issues:** Proposer losing access to keys or becoming inactive
5. **Deliberate Griefing:** Malicious actors intentionally waiting for expiration to block governance

**Detection Constraints:**
Tests validate that expired proposals can be cleared, but do not check the scenario where approved proposals are cleared: [8](#0-7) 

### Recommendation

**Code-Level Mitigation:**

Modify the `ClearProposal` function to prevent deletion of proposals that have reached their release threshold:

```csharp
public override Empty ClearProposal(Hash input)
{
    var proposal = State.Proposals[input];
    Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
    
    // NEW: Check if proposal has reached release threshold
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(!IsReleaseThresholdReached(proposal, organization), 
        "Cannot clear approved proposal - must be released first");
    
    State.Proposals.Remove(input);
    return new Empty();
}
```

**Alternative Approach:**

Allow approved proposals to be auto-released by anyone after expiration:

```csharp
public override Empty ClearProposal(Hash input)
{
    var proposal = State.Proposals[input];
    Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
    
    var organization = State.Organizations[proposal.OrganizationAddress];
    
    // If approved, execute instead of clearing
    if (IsReleaseThresholdReached(proposal, organization))
    {
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken),
            proposal.ToAddress, proposal.ContractMethodName, proposal.Params);
        Context.Fire(new ProposalReleased { ProposalId = input });
    }
    
    State.Proposals.Remove(input);
    return new Empty();
}
```

**Invariant Checks:**
- Add assertion that proposals reaching release threshold are either released or remain in state until manually cleared by authorized parties
- Validate that `ToBeReleased = true` proposals cannot be deleted without execution

**Test Cases:**
1. Test that `ClearProposal` fails when called on an expired proposal that has reached release threshold
2. Test that approved proposals can still be released after expiration (if using auto-release approach)
3. Test that only non-approved expired proposals can be cleared
4. Add regression tests verifying the governance invariant that approved decisions are executable

Apply the same fix to Association and Referendum contracts.

### Proof of Concept

**Initial State:**
- Parliament contract initialized with default organization
- Three parliament members (miners) available for voting
- Organization threshold: MinimalApprovalThreshold = 6667 (66.67% approval required)

**Exploit Sequence:**

1. **Day 0:** Proposer creates a governance proposal to transfer 1000 ELF tokens
   - Proposal ID: `0xABC...`
   - ExpiredTime: Current time + 2 days
   - State: ToBeReleased = false

2. **Day 1:** Two out of three parliament members approve the proposal (66.67% approval)
   - Approval count meets MinimalApprovalThreshold
   - Query `GetProposal`: ToBeReleased = **true**
   - Proposal is ready for execution via `Release`

3. **Day 2:** Proposer is busy and doesn't call `Release` before expiration
   - Current time > ExpiredTime
   - Proposal still exists with ToBeReleased = true

4. **Day 2 + 1 hour:** Anyone (including attacker) calls `ClearProposal(0xABC...)`
   - Transaction succeeds (only checks expiration)
   - Proposal removed from state
   - Query `GetProposal`: Returns empty ProposalOutput

**Expected Result:**
`ClearProposal` should fail with error: "Cannot clear approved proposal"

**Actual Result:**
`ClearProposal` succeeds and permanently deletes the approved proposal without execution, preventing the 1000 ELF transfer that was democratically approved by parliament members.

**Success Condition:**
The approved governance decision is lost, requiring complete re-voting from scratch. All previous voting effort is wasted, and the token transfer never occurs.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-145)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

        return new Empty();
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L225-248)
```csharp
    public override ProposalOutput GetProposal(Hash proposalId)
    {
        var proposal = State.Proposals[proposalId];
        if (proposal == null) return new ProposalOutput();

        var organization = State.Organizations[proposal.OrganizationAddress];

        return new ProposalOutput
        {
            ProposalId = proposalId,
            ContractMethodName = proposal.ContractMethodName,
            ExpiredTime = proposal.ExpiredTime,
            OrganizationAddress = proposal.OrganizationAddress,
            Params = proposal.Params,
            Proposer = proposal.Proposer,
            ToAddress = proposal.ToAddress,
            ToBeReleased = Validate(proposal) && IsReleaseThresholdReached(proposal, organization),
            ApprovalCount = proposal.Approvals.Count,
            RejectionCount = proposal.Rejections.Count,
            AbstentionCount = proposal.Abstentions.Count,
            Title = proposal.Title,
            Description = proposal.Description
        };
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L36-48)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var parliamentMembers = GetCurrentMinerList();
        var isRejected = IsProposalRejected(proposal, organization, parliamentMembers);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization, parliamentMembers);
        if (isAbstained)
            return false;

        return CheckEnoughVoteAndApprovals(proposal, organization, parliamentMembers);
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

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L923-945)
```csharp
    [Fact]
    public async Task Clear_ExpiredProposal_Test()
    {
        // await InitializeParliamentContracts();

        var minimalApprovalThreshold = 6667;
        var maximalAbstentionThreshold = 2000;
        var maximalRejectionThreshold = 3000;
        var minimalVoteThreshold = 8000;
        var organizationAddress = await CreateOrganizationAsync(minimalApprovalThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, minimalVoteThreshold);
        var proposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);

        ParliamentContractStub = GetParliamentContractTester(InitialMinersKeyPairs[0]);
        BlockTimeProvider.SetBlockTime(BlockTimeProvider.GetBlockTime().AddDays(5));
        var error = await ParliamentContractStub.Approve.CallWithExceptionAsync(proposalId);
        error.Value.ShouldContain("Invalid proposal.");

        var clear = await ParliamentContractStub.ClearProposal.SendAsync(proposalId);
        clear.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        var proposal = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
        proposal.ShouldBe(new ProposalOutput());
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L1540-1549)
```csharp
        var createProposalInput = new CreateProposalInput
        {
            ContractMethodName = nameof(TokenContractStub.Transfer),
            ToAddress = TokenContractAddress,
            Params = transferInput.ToByteString(),
            ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(2),
            OrganizationAddress = organizationAddress,
            Title = "Token Transfer",
            Description = "Transfer 100 ELF to Tester's address",
        };
```
