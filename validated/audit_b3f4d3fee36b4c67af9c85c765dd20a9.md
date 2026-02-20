# Audit Report

## Title
Parliament Proposal Threshold Calculations Use Dynamic Miner Count Leading to Incorrect Approval/Rejection Outcomes

## Summary
The Parliament contract calculates proposal approval thresholds using the current miner list count at release time rather than when votes were cast. When the parliament size changes during consensus term transitions, proposals that legitimately met approval thresholds can fail to release, or proposals that should be rejected can pass, violating governance integrity.

## Finding Description

The Parliament contract stores proposal votes as address lists without snapshotting the parliament size at creation time. The `ProposalInfo` structure stores only voter addresses in `approvals`, `rejections`, and `abstentions` fields with no parliament size snapshot. [1](#0-0) 

When the `Release()` method validates a proposal, it calls `IsReleaseThresholdReached()` which immediately retrieves the CURRENT miner list dynamically. [2](#0-1) [3](#0-2) 

The `GetCurrentMinerList()` method calls the consensus contract's view method, which returns miners from the current round's `RealTimeMinersInformation` dictionary keys, making it inherently dynamic. [4](#0-3) [5](#0-4) 

All threshold calculations use `parliamentMembers.Count` as the denominator, representing the current parliament size at check time:
- Rejection threshold: [6](#0-5) 
- Abstention threshold: [7](#0-6) 
- Approval threshold: [8](#0-7) 
- Vote threshold: [9](#0-8) 

During consensus term transitions via `ProcessNextTerm()`, the miner list is updated by extracting miners from the new round information, which can have a different count than the previous term. [10](#0-9) 

The `AbstractVoteTotal` constant is 10000 (basis points), with default thresholds like 6667 for approval (66.67%). [11](#0-10) 

**Concrete Example:**
- A proposal receives 7 approvals from a 9-member parliament (77.8%)
- Calculation: `7 * 10000 >= 6667 * 9` → `70000 >= 59,003` ✓ (passes)
- Parliament grows to 12 members during term transition
- Same 7 votes now: `7 * 10000 >= 6667 * 12` → `70000 >= 80,004` ✗ (fails)

## Impact Explanation

**Governance Integrity Violation:**
This vulnerability breaks the fundamental invariant that proposals meeting approval thresholds should be executable. Votes cast under one parliament composition are evaluated under a different composition, leading to:

1. **Legitimate proposals failing**: Proposals with sufficient approval percentages at vote time can become unreleasable after parliament growth
2. **Invalid approvals**: Proposals can be incorrectly approved when parliament shrinks, even if they lacked valid approval margins at vote time
3. **Unpredictable outcomes**: Governance becomes unreliable as proposal success depends on timing relative to term transitions

**Affected Components:**
- Default parliament organization (controls system governance via Genesis contract)
- Custom parliament organizations 
- Emergency response organization (90% thresholds - even more sensitive)
- All critical operations: system upgrades, configuration changes, cross-chain operations, treasury management

**Severity: HIGH** because it:
- Affects core protocol governance without requiring attacker privileges
- Can block critical system upgrades and emergency responses
- Operates silently - proposals appear valid but fail unexpectedly
- Impacts all parliament-governed operations across the ecosystem

## Likelihood Explanation

**Natural Occurrence:**
Term transitions in AEDPoS consensus happen regularly with `PeriodSeconds` defaulting to 604800 seconds (7 days). [12](#0-11) 

The consensus initialization confirms term changes are expected in production: `IsTermStayOne` is false on mainchain (set to `int.MaxValue` only when true for tests), and `State.IsMainChain.Value = true` is set when term changes are enabled. [13](#0-12) 

**Feasibility:**
- No special attacker capabilities required
- Happens through normal blockchain operations
- Any user can call `Release()` after apparent threshold satisfaction
- Timing windows are predictable (term boundaries every 7 days)

**Probability: HIGH** - This will occur whenever:
1. A proposal is created before a term transition
2. The miner count changes during the transition (election results vary)
3. The vote count is near threshold boundaries
4. Release is attempted after the transition

Given weekly term transitions and multi-day proposal lifetimes, this scenario is inevitable in normal operations.

## Recommendation

Add a parliament size snapshot to the `ProposalInfo` structure and use it in threshold calculations:

1. **Modify ProposalInfo**: Add `int32 parliament_member_count_at_creation` field
2. **Snapshot on creation**: In `CreateNewProposal()`, store `GetCurrentMinerList().Count`
3. **Use snapshot for thresholds**: Modify `IsReleaseThresholdReached()` to use `proposal.ParliamentMemberCountAtCreation` instead of calling `GetCurrentMinerList()`
4. **Validate votes**: Only count votes from addresses that were parliament members at proposal creation time

Alternative: Use round number/term number at creation and retrieve the historical miner list, though this requires storing historical miner lists longer.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task ProposalThresholdChangesWithParliamentSize()
{
    // Setup: Create parliament with 9 members
    var initialMiners = GenerateMiners(9);
    await InitializeConsensusWithMiners(initialMiners);
    
    // Create proposal and get 7 approvals (77.8% > 66.67% threshold)
    var proposalId = await CreateTestProposal();
    for (int i = 0; i < 7; i++)
    {
        await ApproveProposalAs(proposalId, initialMiners[i]);
    }
    
    // Verify proposal would be releasable now
    var proposalOutput = await GetProposal(proposalId);
    Assert.True(proposalOutput.ToBeReleased); // Should pass with 7/9 votes
    
    // Trigger term transition with 12 members
    var newMiners = GenerateMiners(12);
    await TransitionToNextTerm(newMiners);
    
    // Try to release - should fail even though it had sufficient votes
    var releaseResult = await ReleaseProposal(proposalId);
    
    // Assertion: Release fails because 7 * 10000 < 6667 * 12
    // 70000 < 80004 - proposal that was approved now fails
    Assert.False(releaseResult.Success);
    Assert.Contains("Not approved", releaseResult.Error);
}
```

**Notes**

This vulnerability is particularly severe for the Emergency Response Organization which requires 90% approval thresholds, making it even more sensitive to parliament size changes. The issue affects not just proposal approval, but also rejection and abstention thresholds, meaning proposals could be incorrectly rejected when parliament shrinks. The lack of any parliament size snapshotting mechanism is a fundamental design flaw in the Parliament contract's governance model.

### Citations

**File:** protobuf/parliament_contract.proto (L131-136)
```text
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
```

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L13-20)
```csharp
    private List<Address> GetCurrentMinerList()
    {
        RequireConsensusContractStateSet();
        var miner = State.ConsensusContract.GetCurrentMinerList.Call(new Empty());
        var members = miner.Pubkeys.Select(publicKey =>
            Address.FromPublicKey(publicKey.ToByteArray())).ToList();
        return members;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L64-70)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var rejectionMemberCount = proposal.Rejections.Count(parliamentMembers.Contains);
        return rejectionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L72-78)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(parliamentMembers.Contains);
        return abstentionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalAbstentionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L80-92)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached = IsVoteThresholdReached(proposal, organization, parliamentMembers);
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L94-102)
```csharp
    private bool IsVoteThresholdReached(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L31-42)
```csharp
    public override MinerList GetCurrentMinerList(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var round)
            ? new MinerList
            {
                Pubkeys =
                {
                    round.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k))
                }
            }
            : new MinerList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-9)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L12-12)
```csharp
    public long PeriodSeconds { get; set; } = 604800;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L27-43)
```csharp
        State.PeriodSeconds.Value = input.IsTermStayOne
            ? int.MaxValue
            : input.PeriodSeconds;

        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;

        Context.LogDebug(() => $"There are {State.PeriodSeconds.Value} seconds per period.");

        if (input.IsSideChain) InitialProfitSchemeForSideChain(input.PeriodSeconds);

        if (input.IsTermStayOne || input.IsSideChain)
        {
            State.IsMainChain.Value = false;
            return new Empty();
        }

        State.IsMainChain.Value = true;
```
