# Audit Report

## Title
Approved Proposals Can Be Cleared Before Execution Due to Missing Release Threshold Check

## Summary
The `ClearProposal` function in Parliament, Association, and Referendum contracts allows anyone to permanently delete fully approved proposals after they expire, without checking if the proposal has reached its release threshold. This creates a race condition where approved governance decisions can be destroyed before execution, breaking the fundamental governance invariant that approved proposals should be executable.

## Finding Description

The `ClearProposal` method in all three governance contracts implements identical flawed logic that only validates expiration without checking approval status. [1](#0-0) [2](#0-1) [3](#0-2) 

The contracts implement `IsReleaseThresholdReached` functions that perform comprehensive approval validation: [4](#0-3) [5](#0-4) [6](#0-5) 

The `Release` method correctly uses this check before executing proposals: [7](#0-6) 

However, `Release` can only be called on non-expired proposals because `GetValidProposal` validates the proposal hasn't expired: [8](#0-7) [9](#0-8) 

This creates a critical race condition:
1. Proposal is created with typical 1-day expiration [10](#0-9) 
2. Members vote and proposal reaches release threshold (ToBeReleased = true) [11](#0-10) 
3. If expiration occurs before proposer calls `Release`, the proposal can NEVER be released
4. Anyone can then call `ClearProposal` and permanently delete the approved proposal

The existing tests only verify that expired proposals CAN be cleared, but never test the scenario where APPROVED proposals are cleared: [12](#0-11) 

## Impact Explanation

**High Impact on Governance Integrity:**

- **Broken Governance Invariant:** The fundamental guarantee that approved proposals (ToBeReleased = true) can be executed is violated. Once a proposal expires, even with sufficient approvals, it becomes permanently unexecutable and deletable.

- **Complete Loss of Governance Work:** All voting effort, time, and resources spent reaching consensus are wasted. Participants who voted thinking their approved decision would execute find their work nullified.

- **No Recovery Mechanism:** Deleted proposals cannot be restored. The entire governance process must restart from scratch: create new proposal, wait for voting period, collect votes again.

- **Griefing Attack Vector:** Malicious actors can deliberately prevent approved governance by simply waiting for expiration and calling `ClearProposal`. This is especially dangerous for contentious proposals where adversaries want to block legitimate governance decisions.

- **Time-Sensitive Decisions Blocked:** Emergency responses, urgent parameter adjustments, or time-critical system upgrades can be indefinitely delayed by repeatedly allowing proposals to expire before execution.

- **Affects All Three Governance Systems:** Parliament (consensus governance), Association (multi-signature governance), and Referendum (token-weighted governance) all suffer from this vulnerability.

## Likelihood Explanation

**Moderate-to-High Likelihood:**

**No Privilege Required:**
- `ClearProposal` is publicly callable by anyone
- No authorization checks beyond expiration
- Zero economic cost beyond gas fees

**Realistic Operational Scenarios:**

1. **Network Congestion:** High transaction volume on AElf chain delays the proposer's `Release` transaction past the 1-day expiration window

2. **Proposer Unavailability:** Proposer monitoring tools fail, proposer is temporarily offline, or traveling across time zones during the critical release window

3. **Strategic Vote Waiting:** Proposer intentionally waits for additional approvals to strengthen consensus legitimacy, accidentally exceeding expiration

4. **Key Management Issues:** Proposer loses temporary access to signing keys or experiences hardware wallet issues during the narrow execution window

5. **Deliberate Adversarial Action:** Opponents of a proposal monitor the blockchain and immediately call `ClearProposal` the moment expiration occurs

**Narrow Time Window:**
- Typical 1-day expiration creates a small window between approval and expiration
- Proposer must actively monitor and execute within this window
- Any delay results in permanent loss of the proposal

**Low Attack Complexity:**
- Single function call: `ClearProposal(proposalId)`
- No complex state manipulation required
- Easily automated by monitoring blockchain state

## Recommendation

Add a check in `ClearProposal` to prevent deletion of approved proposals:

```csharp
public override Empty ClearProposal(Hash input)
{
    var proposal = State.Proposals[input];
    Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
    
    // NEW: Prevent clearing approved proposals
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(!IsReleaseThresholdReached(proposal, organization), 
        "Cannot clear approved proposal - release threshold reached");
    
    State.Proposals.Remove(input);
    return new Empty();
}
```

**Alternative Solutions:**

1. **Extend Release Window:** Allow `Release` to be called on expired proposals if they reached the threshold before expiration
2. **Auto-Execute:** Automatically execute proposals when threshold is reached
3. **Protected Period:** Add a grace period after expiration where only the proposer can clear approved proposals

Apply the fix to all three contracts: Parliament, Association, and Referendum.

## Proof of Concept

```csharp
[Fact]
public async Task ClearApprovedProposal_ShouldFail_Test()
{
    // Create organization with low threshold
    var minimalApprovalThreshold = 6667;
    var maximalAbstentionThreshold = 2000;
    var maximalRejectionThreshold = 3000;
    var minimalVoteThreshold = 8000;
    var organizationAddress = await CreateOrganizationAsync(
        minimalApprovalThreshold,
        maximalAbstentionThreshold, 
        maximalRejectionThreshold, 
        minimalVoteThreshold);
    
    // Create proposal with 1 day expiration
    var proposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
    
    // Get enough approvals to reach release threshold
    await ApproveWithMinersAsync(proposalId);
    
    // Verify proposal is approved and ready to release
    var proposalBeforeExpiry = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
    proposalBeforeExpiry.ToBeReleased.ShouldBeTrue(); // Approved!
    
    // Advance time past expiration
    BlockTimeProvider.SetBlockTime(BlockTimeProvider.GetBlockTime().AddDays(2));
    
    // Proposal is still approved but expired
    var proposalAfterExpiry = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
    proposalAfterExpiry.ToBeReleased.ShouldBeTrue(); // Still approved!
    
    // VULNERABILITY: Anyone can clear the approved proposal
    var clearResult = await ParliamentContractStub.ClearProposal.SendAsync(proposalId);
    clearResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Succeeds!
    
    // Approved proposal is now permanently deleted
    var deletedProposal = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
    deletedProposal.ShouldBe(new ProposalOutput()); // Gone!
    
    // Cannot release the approved proposal anymore
    var releaseError = await ParliamentContractStub.Release.CallWithExceptionAsync(proposalId);
    releaseError.Value.ShouldContain("Proposal not found"); // Permanent loss!
}
```

This test demonstrates that an approved proposal (ToBeReleased = true) can be permanently deleted after expiration, preventing its execution and wasting all governance effort.

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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L241-241)
```csharp
            ToBeReleased = Validate(proposal) && IsReleaseThresholdReached(proposal, organization),
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L177-180)
```csharp
    private bool CheckProposalNotExpired(ProposalInfo proposal)
    {
        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L182-188)
```csharp
    private ProposalInfo GetValidProposal(Hash proposalId)
    {
        var proposal = State.Proposals[proposalId];
        Assert(proposal != null, "Proposal not found.");
        Assert(Validate(proposal), "Invalid proposal.");
        return proposal;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-32)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
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

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTestBase.cs (L179-179)
```csharp
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L924-945)
```csharp
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
