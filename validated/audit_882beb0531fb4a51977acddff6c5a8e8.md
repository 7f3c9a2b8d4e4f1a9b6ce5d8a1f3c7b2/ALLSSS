# Audit Report

## Title
Stale Miner List in Parliament Threshold Calculations Causes Incorrect Proposal Approval/Rejection

## Summary
The Parliament contract contains a time-of-check-time-of-use (TOCTOU) vulnerability where votes are counted against the current miner list at release time rather than the miner list when votes were cast. This causes proposals to incorrectly pass or fail when consensus term changes occur during the voting period, violating governance integrity.

## Finding Description

The vulnerability exists in the Parliament contract's threshold calculation mechanism. When `Release()` is invoked, it calls `IsReleaseThresholdReached()` to verify if the proposal meets approval thresholds. [1](#0-0) 

The `IsReleaseThresholdReached()` method fetches the **current** miner list at the time of release: [2](#0-1) 

This current miner list is retrieved from the consensus contract: [3](#0-2) 

The current miner list is then used to filter which votes are counted in all threshold calculations:

**Rejection threshold:** [4](#0-3) 

**Abstention threshold:** [5](#0-4) 

**Approval threshold:** [6](#0-5) 

**Vote threshold:** [7](#0-6) 

The root cause is that votes are stored as simple address lists without term or round context: [8](#0-7) 

During voting, miners cast votes that are recorded in these lists: [9](#0-8) 

However, the miner list changes when term transitions occur. The consensus contract updates the miner list for new terms: [10](#0-9) 

The `GetCurrentMinerList()` method returns miners from the current round information, which reflects the most recent term's composition: [11](#0-10) 

Terms last 604,800 seconds (7 days) by default: [12](#0-11) 

**Attack Scenario:**
1. A proposal is created in Term N requiring 70% approval
2. Seven miners (70%) vote to approve during Term N
3. Term N+1 begins, and four of those approving miners are replaced through election
4. When `Release()` is called, only three approval votes are counted (from miners still active)
5. The proposal incorrectly fails with 30% approval despite having received sufficient votes when cast

## Impact Explanation

This vulnerability has **HIGH** severity impact as it directly compromises governance integrity, which is a critical security guarantee of the Parliament contract.

**Governance Integrity Violation**: The fundamental expectation is that if sufficient miners vote to approve a proposal, it should be executable. This vulnerability breaks that guarantee by retroactively invalidating votes from miners who were legitimate at voting time but were subsequently replaced.

**Dual Impact:**
1. **Legitimate proposals incorrectly rejected**: Proposals that received sufficient approval from active miners can fail if those miners are no longer active at release time
2. **Malicious proposals incorrectly approved**: Proposals that received sufficient rejections to block them can pass if the rejecting miners are replaced before release

**Affected Operations**: All Parliament-governed operations are vulnerable, including:
- System contract upgrades
- Contract deployments and authorizations
- Economic parameter adjustments (mining rewards, fee rates)
- Cross-chain configurations
- Treasury and profit pool modifications

The impact extends to the entire AElf ecosystem as Parliament is the primary governance mechanism for critical system-level decisions.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of occurrence because it requires no attacker privileges or complex exploit sequences—it manifests naturally during normal protocol operations.

**No Special Privileges Required**: Any address authorized to create proposals can trigger this vulnerability. The attacker simply creates a proposal with an expiration time that spans a term boundary.

**Low Attack Complexity**: The exploit path is trivial:
1. Create a proposal through normal governance channels
2. Wait for natural term transition (occurs automatically every 7 days)
3. Release the proposal after the term change

**Highly Feasible Conditions**:
- Term changes occur automatically every 604,800 seconds (7 days)
- Governance proposals typically require discussion periods longer than 7 days for proper community review
- Miner list changes are guaranteed during elections, with significant turnover common in validator elections
- No expiration time limits prevent proposals from spanning term boundaries

**Natural Occurrence**: This vulnerability will manifest without any attacker action whenever:
- A proposal's voting period spans a term boundary
- Some miners who voted are replaced in the new term
- The vote shift caused by the miner change alters whether thresholds are met

Given that proposals routinely span multiple weeks while terms are only 7 days, this vulnerability is virtually certain to occur in production governance operations.

## Recommendation

Implement one of the following fixes:

**Option 1: Snapshot Miner List at Proposal Creation**
Store the miner list at proposal creation time and use this snapshot for all vote counting:

```csharp
// In ProposalInfo message
repeated aelf.Address eligible_voters = 14;

// In CreateNewProposal
proposal.EligibleVoters.AddRange(GetCurrentMinerList());

// In IsReleaseThresholdReached
var parliamentMembers = proposal.EligibleVoters; // Use snapshot instead of GetCurrentMinerList()
```

**Option 2: Add Term/Round Context to Votes**
Store the term number when each vote is cast and only count votes from the term when the proposal was created:

```csharp
// In ProposalInfo message
int64 creation_term_number = 14;
map<string, int64> approval_terms = 15;

// Validate votes match creation term during release
```

**Option 3: Enforce Maximum Proposal Lifetime**
Limit proposal expiration times to be less than one term duration:

```csharp
// In CreateNewProposal
var currentTermStartTime = GetCurrentTermStartTime();
var termEndTime = currentTermStartTime.AddSeconds(State.PeriodSeconds.Value);
Assert(input.ExpiredTime < termEndTime, "Proposal cannot span term boundary");
```

## Proof of Concept

```csharp
[Fact]
public async Task TestStaleMinerListCausesIncorrectProposalRejection()
{
    // Setup: 10 miners in Term N
    var initialMiners = GenerateMinerList(10);
    await InitializeConsensusWithMiners(initialMiners);
    
    // Create proposal requiring 70% approval (7 out of 10 miners)
    var proposalId = await CreateParliamentProposal(
        approvalThreshold: 7000, // 70%
        expirationDays: 14 // Spans term boundary
    );
    
    // 7 miners approve in Term N (70% - should pass)
    for (int i = 0; i < 7; i++)
    {
        await ApproveProposal(proposalId, initialMiners[i]);
    }
    
    // Verify proposal is ready for release
    var proposalBeforeTermChange = await GetProposal(proposalId);
    Assert.True(proposalBeforeTermChange.ToBeReleased);
    
    // Advance time to trigger term transition (7 days)
    await AdvanceTime(604800);
    
    // Term N+1: Replace 4 of the 7 approving miners with new miners
    var newMiners = GenerateMinerList(10);
    for (int i = 0; i < 4; i++)
    {
        newMiners[i] = GenerateNewMiner(); // Replace 4 miners
    }
    await ExecuteTermTransition(newMiners);
    
    // Verify only 3 approval votes now counted (from miners still active)
    var proposalAfterTermChange = await GetProposal(proposalId);
    Assert.Equal(3, proposalAfterTermChange.ApprovalCount); // Only 3 of original 7 still active
    
    // Attempt to release - should fail despite having sufficient votes when cast
    var releaseResult = await ReleaseProposal(proposalId);
    Assert.False(releaseResult.Success); // Vulnerability: Incorrectly fails
    Assert.Contains("Not approved", releaseResult.Error);
    
    // Expected: Proposal should pass because 7 out of 10 miners approved when votes were cast
    // Actual: Proposal fails because only 3 out of 10 current miners have approval votes
}
```

## Notes

This vulnerability fundamentally violates the governance security guarantee that "votes cast by authorized miners should determine proposal outcomes." The TOCTOU race condition between voting and release allows miner list changes to retroactively invalidate legitimate votes, enabling both denial-of-service on legitimate governance and potential approval of malicious proposals that should be blocked.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L78-94)
```csharp
    public override Empty Approve(Hash input)
    {
        var parliamentMemberAddress = GetAndCheckActualParliamentMemberAddress();
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedByMember(proposal, parliamentMemberAddress);
        proposal.Approvals.Add(parliamentMemberAddress);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = parliamentMemberAddress,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Approve),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
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

**File:** protobuf/parliament_contract.proto (L116-143)
```text
message ProposalInfo {
    // The proposal ID.
    aelf.Hash proposal_id = 1;
    // The method that this proposal will call when being released.
    string contract_method_name = 2;
    // The address of the target contract.
    aelf.Address to_address = 3;
    // The parameters of the release transaction.
    bytes params = 4;
    // The date at which this proposal will expire.
    google.protobuf.Timestamp expired_time = 5;
    // The address of the proposer of this proposal.
    aelf.Address proposer = 6;
    // The address of this proposals organization.
    aelf.Address organization_address = 7;
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
    // Url is used for proposal describing.
    string proposal_description_url = 11;
    // Title of this proposal.
    string title = 12;
    // Description of this proposal.
    string description = 13;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L12-12)
```csharp
    public long PeriodSeconds { get; set; } = 604800;
```
