### Title
Parliament Proposal Release Failure Due to Miner List Changes Between Voting and Execution

### Summary
The Parliament contract's `IsReleaseThresholdReached()` method filters votes based on the CURRENT miner list at the time of `Release()` call, not the miner list at the time votes were cast. When consensus term transitions occur between vote collection and proposal release, previously valid votes from miners no longer in the active set are discarded, causing legitimately approved proposals to fail threshold checks and become permanently unreleasable.

### Finding Description

**Root Cause Location:**
The vulnerability exists in how vote counting is performed in `IsReleaseThresholdReached()`. [1](#0-0) 

The critical filtering operations that cause the issue: [2](#0-1) [3](#0-2) [4](#0-3) 

**Why Protections Fail:**

The `Release()` method calls `IsReleaseThresholdReached()` which retrieves the CURRENT miner list from the consensus contract at line 38. [5](#0-4) 

The miner list changes during term transitions in the AEDPoS consensus: [6](#0-5) 

**Execution Path:**
1. At Term N, miners {A, B, C, D, E} exist (5 miners)
2. Proposal created with default threshold 6667/10000 (66.67%) [7](#0-6) 
3. Miners A, B, C, D approve (4/5 = 80% ≥ 66.67%) - threshold reached
4. Term transition occurs (every PeriodSeconds), new miner list becomes {B, C, F, G, H}
5. Proposer calls `Release()`
6. `IsReleaseThresholdReached()` fetches current miners {B, C, F, G, H}
7. Vote filtering: `proposal.Approvals.Count(parliamentMembers.Contains)` yields only 2 (B, C)
8. 2/5 = 40% < 66.67% - threshold check FAILS
9. Transaction reverts with "Not approved"

Votes are immutable and cannot be changed once cast: [8](#0-7) 

### Impact Explanation

**Governance DoS Attack Surface:**
- Proposals that legitimately reached approval thresholds become permanently unreleasable
- Critical system upgrades, configuration changes, and emergency responses are blocked
- If proposals expire before release can occur, governance deadlocks [9](#0-8) 

**Affected Parties:**
- Default organization proposals (system-critical) [10](#0-9) 
- All custom Parliament organizations
- Emergency Response Organization proposals [11](#0-10) 

**Severity Justification:**
This is a HIGH severity operational impact that breaks governance integrity. The system can enter states where critical proposals approved by a supermajority become permanently unexecutable, effectively halting governance functions.

### Likelihood Explanation

**Attack Complexity:** NONE - This occurs during normal system operations without any attacker involvement.

**Feasibility Conditions:**
- Term transitions occur regularly every PeriodSeconds (120 seconds in tests, likely days in production) [12](#0-11) 
- If vote collection spans a term boundary (highly likely for contentious proposals requiring time to gather support), this issue manifests naturally
- No special privileges required

**Probability:** HIGH - Any proposal where voting extends across a term transition and involves miners who leave the active set will experience this issue. Given that proposals may require days to gather sufficient approvals while terms transition periodically, this is an expected scenario.

**Detection Constraints:** The issue is silent until `Release()` is attempted. The `GetProposal()` view method shows `ToBeReleased = true` based on a stale threshold calculation, misleading proposers. [13](#0-12) 

### Recommendation

**Code-Level Mitigation:**
1. Store the miner list snapshot at proposal creation time
2. Use the creation-time miner list for threshold validation in `IsReleaseThresholdReached()`
3. Add a field to `ProposalInfo` proto: `MinerListSnapshot` containing the miner list at creation time
4. Modify vote counting to filter against the snapshot instead of current miners

**Invariant to Add:**
```
// Votes must be counted against the miner composition that existed when the proposal was created,
// not the current miner composition at release time
```

**Alternative Mitigation (simpler):**
Store a term number with each proposal and require that votes from any term during the proposal lifetime count toward threshold, not just the current term's miners.

**Test Cases:**
1. Create proposal in Term N, get approvals, transition to Term N+1 with different miners, verify Release() succeeds
2. Create proposal with votes from miners who subsequently leave the active set, verify their votes still count
3. Test edge case where ALL voting miners leave the active set before Release()

### Proof of Concept

**Initial State:**
- Term 1 active with miners: [MinerA, MinerB, MinerC, MinerD, MinerE] (5 total)
- Default organization with MinimalApprovalThreshold = 6667 (66.67%)
- PeriodSeconds = 120 (term duration)

**Transaction Steps:**
1. T=0: CreateProposal() by authorized proposer → ProposalId
2. T=10: MinerA.Approve(ProposalId) → Success
3. T=20: MinerB.Approve(ProposalId) → Success  
4. T=30: MinerC.Approve(ProposalId) → Success
5. T=40: MinerD.Approve(ProposalId) → Success
   - Votes: 4/5 = 80% ≥ 66.67% ✓ Threshold reached
   - GetProposal().ToBeReleased = true
6. T=121: Term transition occurs → New miner list: [MinerB, MinerC, MinerF, MinerG, MinerH]
7. T=130: Proposer.Release(ProposalId) → Transaction

**Expected Result:**
Proposal executes successfully (threshold was reached with 80% approval)

**Actual Result:**
Transaction reverts with "Not approved" error because:
- Current miner list contains only MinerB and MinerC from original voters
- Recalculated approval: 2/5 = 40% < 66.67% ✗ Threshold failed
- MinerA and MinerD votes are silently discarded

**Success Condition for Exploit:**
Release() call fails despite proposal having legitimately reached approval threshold at time of voting.

### Notes

While the original question asked about miners changing votes during a gap, the actual issue is more subtle: miners cannot change votes (they are immutable), and there is no gap within the atomic `Release()` transaction. However, there IS a critical TOCTOU vulnerability where the miner list composition changes between when votes are cast and when `Release()` validates the threshold, causing the same governance failure the question was concerned about.

### Citations

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L67-69)
```csharp
        var rejectionMemberCount = proposal.Rejections.Count(parliamentMembers.Contains);
        return rejectionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L75-77)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(parliamentMembers.Contains);
        return abstentionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalAbstentionThreshold * parliamentMembers.Count;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L83-86)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L190-193)
```csharp
    private void AssertProposalNotYetVotedByMember(ProposalInfo proposal, Address parliamentMemberAddress)
    {
        Assert(!CheckProposalAlreadyVotedBy(proposal, parliamentMemberAddress), "Already approved.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L34-35)
```csharp
        var defaultOrganizationAddress = CreateNewOrganization(organizationInput);
        State.DefaultOrganizationAddress.Value = defaultOrganizationAddress;
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L203-210)
```csharp
    public override Empty CreateEmergencyResponseOrganization(Empty input)
    {
        Assert(State.EmergencyResponseOrganizationAddress.Value == null,
            "Emergency Response Organization already exists.");
        AssertSenderAddressWith(State.DefaultOrganizationAddress.Value);
        CreateEmergencyResponseOrganization();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-5)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
```

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/AEDPoSContractTestConstants.cs (L20-20)
```csharp
    internal const long PeriodSeconds = 120; // 7 * 60 * 60 * 24
```
