# Audit Report

## Title
Parliament Proposal Threshold Calculations Use Dynamic Miner Count Leading to Incorrect Approval/Rejection Outcomes

## Summary
The Parliament contract calculates proposal approval thresholds using the current miner list count at release time rather than when votes were cast. When the parliament size changes during consensus term transitions, proposals that legitimately met approval thresholds can fail to release, or proposals that should be rejected can pass, violating governance integrity.

## Finding Description

The Parliament contract stores proposal votes as address lists without snapshotting the parliament size at creation time. [1](#0-0) 

When checking if a proposal meets release thresholds, the contract retrieves the CURRENT miner list dynamically from the consensus contract. [2](#0-1) [3](#0-2) 

The consensus contract's `GetCurrentMinerList()` returns miners from the current round's `RealTimeMinersInformation`, making it dynamic. [4](#0-3) 

All threshold calculations use `parliamentMembers.Count` as the denominator, representing the current parliament size at check time:
- Rejection threshold check [5](#0-4) 
- Abstention threshold check [6](#0-5) 
- Approval threshold check [7](#0-6) 
- Vote threshold check [8](#0-7) 

The Release method validates proposals using these dynamic calculations with no safeguards. [9](#0-8) 

During consensus term transitions, the miner list is updated by extracting miners from the new round information, which can have a different count than the previous term. [10](#0-9) 

The AbstractVoteTotal constant is 10000 (basis points), with default thresholds like 6667 for approval (66.67%). [11](#0-10) 

**Concrete Example:**
- A proposal receives 7 approvals from a 9-member parliament (77.8%)
- Calculation: `7 * 10000 >= 6667 * 9` → `70000 >= 59,003` ✓ (passes)
- Parliament grows to 12 members during term transition
- Same 7 votes now: `7 * 10000 >= 6667 * 12` → `70000 >= 80,004` ✗ (fails)

## Impact Explanation

**Governance Integrity Violation:**
This vulnerability breaks the fundamental invariant that proposals meeting approval thresholds should be executable. Votes cast under one parliament composition are evaluated under a different composition, leading to:

1. **Legitimate proposals failing**: Proposals with sufficient approval percentages at vote time can become unreleasable after parliament growth
2. **Invalid rejections**: Proposals can be incorrectly rejected when parliament shrinks, even if they had valid approval margins
3. **Unpredictable outcomes**: Governance becomes unreliable as proposal success depends on timing relative to term transitions

**Affected Components:**
- Default parliament organization (system governance)
- Custom parliament organizations 
- Emergency response organization
- All critical operations: system upgrades, configuration changes, cross-chain operations, treasury management

**Severity: HIGH** because it:
- Affects core protocol governance without requiring attacker privileges
- Can block critical system upgrades and emergency responses
- Operates silently - proposals appear valid but fail unexpectedly
- Impacts all parliament-governed operations across the ecosystem

## Likelihood Explanation

**Natural Occurrence:**
Term transitions in AEDPoS consensus happen regularly with PeriodSeconds defaulting to 604800 (7 days). [12](#0-11) 

Proposals typically have 1-day expiration windows that overlap with term transitions. [13](#0-12) 

The consensus initialization confirms term changes are expected in production (IsTermStayOne = false on mainchain, true only in tests). [14](#0-13) [15](#0-14) 

**Feasibility:**
- No special attacker capabilities required
- Happens through normal blockchain operations
- Any user can call Release() after apparent threshold satisfaction
- Timing windows are predictable (term boundaries every 7 days)

**Probability: HIGH** - This will occur whenever:
1. A proposal is created before a term transition
2. The miner count changes during the transition
3. The vote count is near threshold boundaries
4. Release is attempted after the transition

Given weekly term transitions and multi-day proposal lifetimes, this scenario is inevitable in normal operations.

## Recommendation

**Add parliament size snapshotting at proposal creation time:**

1. Extend ProposalInfo to include a snapshot field:
```protobuf
message ProposalInfo {
    // ... existing fields ...
    int32 parliament_size_at_creation = 14;
}
```

2. Snapshot the parliament size when creating proposals:
```csharp
private Hash CreateNewProposal(CreateProposalInput input)
{
    // ... existing validation ...
    var currentMinerList = GetCurrentMinerList();
    var proposal = new ProposalInfo
    {
        // ... existing fields ...
        ParliamentSizeAtCreation = currentMinerList.Count
    };
    // ... rest of method ...
}
```

3. Use the snapshotted size in threshold calculations:
```csharp
private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
{
    var parliamentMembers = GetCurrentMinerList();
    var parliamentSize = proposal.ParliamentSizeAtCreation > 0 
        ? proposal.ParliamentSizeAtCreation 
        : parliamentMembers.Count; // fallback for old proposals
    
    var isRejected = IsProposalRejected(proposal, organization, parliamentMembers, parliamentSize);
    // ... update all threshold checks to use parliamentSize instead of parliamentMembers.Count
}
```

This ensures votes are evaluated against the same parliament size under which they were cast, maintaining governance integrity across term transitions.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Create a parliament organization with 9 initial miners
2. Create a proposal requiring 66.67% approval (6667/10000)
3. Have 7 miners approve (77.8% of 9 members = passes threshold)
4. Simulate a term transition that increases parliament to 12 members
5. Attempt to Release() the proposal
6. Observe that the same 7 approvals now represent only 58.3% (7/12), failing the 66.67% threshold
7. Verify the Release() call reverts with "Not approved" despite the proposal having legitimate approval when votes were cast

The test would require:
- Parliament contract initialization
- Consensus contract with term transition capability  
- Ability to simulate NextTerm with modified miner list
- Verification that identical vote counts produce different outcomes based solely on parliament size changes

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-194)
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

```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L1-10)
```csharp
namespace AElf.Contracts.Parliament;

public partial class ParliamentContract
{
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
}
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L1-14)
```csharp
using System.Collections.Generic;
using Google.Protobuf.WellKnownTypes;

namespace AElf.Kernel.Consensus.AEDPoS;

// ReSharper disable once InconsistentNaming
public class ConsensusOptions
{
    public List<string> InitialMinerList { get; set; }
    public int MiningInterval { get; set; }
    public Timestamp StartTimestamp { get; set; } = new() { Seconds = 0 };
    public long PeriodSeconds { get; set; } = 604800;
    public long MinerIncreaseInterval { get; set; } = 31536000;
}
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTestBase.cs (L151-161)
```csharp
    private async Task InitializeConsensusAsync()
    {
        await ConsensusContractStub.InitialAElfConsensusContract.SendAsync(new InitialAElfConsensusContractInput
        {
            IsTermStayOne = true
        });
        var minerList = new MinerList
            { Pubkeys = { InitialMinersKeyPairs.Select(m => ByteStringHelper.FromHexString(m.PublicKey.ToHex())) } };
        await ConsensusContractStub.FirstRound.SendAsync(
            minerList.GenerateFirstRoundOfNewTerm(MiningInterval, BlockchainStartTime));
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTestBase.cs (L172-184)
```csharp
    internal async Task<Hash> CreateParliamentProposalAsync(string method, Address organizationAddress,
        IMessage input, Address toAddress = null)
    {
        var proposal = (await ParliamentContractStub.CreateProposal.SendAsync(new CreateProposalInput
        {
            ToAddress = toAddress,
            ContractMethodName = method,
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = organizationAddress,
            Params = input.ToByteString()
        })).Output;
        return proposal;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L22-41)
```csharp
    public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
    {
        Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;

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
```
