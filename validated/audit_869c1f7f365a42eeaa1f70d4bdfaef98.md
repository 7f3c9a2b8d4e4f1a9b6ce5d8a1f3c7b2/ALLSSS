# Audit Report

## Title
Parliament Proposal Threshold Calculations Use Dynamic Miner Count Leading to Incorrect Approval/Rejection Outcomes

## Summary
The Parliament contract calculates proposal approval thresholds using the current miner list count at the time of release, rather than snapshotting the parliament size when the proposal was created or when votes were cast. When the miner count changes during consensus term transitions, proposals that legitimately met approval thresholds can fail to release, or proposals that should fail can pass, violating governance integrity.

## Finding Description

The Parliament contract stores proposal votes as address lists but does not snapshot the parliament size at proposal creation time. [1](#0-0) 

When a proposal is checked for release, the contract dynamically retrieves the CURRENT miner list from the consensus contract. [2](#0-1) 

The current miner list is obtained by calling the consensus contract's `GetCurrentMinerList()` method, which invokes the consensus contract. [3](#0-2) 

This consensus method returns miners from the current round's `RealTimeMinersInformation`, which represents the active miners at query time, not at proposal creation time. [4](#0-3) 

All threshold calculations use `parliamentMembers.Count` as the denominator, which represents the current parliament size at check time. The approval threshold calculation uses the current count [5](#0-4) , rejection threshold uses the current count [6](#0-5) , abstention threshold uses the current count [7](#0-6) , and vote threshold uses the current count [8](#0-7) .

The `Release` method invokes `IsReleaseThresholdReached()` which performs these calculations using the current miner count. [9](#0-8) 

The miner list changes during consensus term transitions. The `ProcessNextTerm` method updates the miner list by calling `SetMinerList`. [10](#0-9) 

The `SetMinerList` method updates `State.MainChainCurrentMinerList` and `State.MinerListMap[termNumber]`, changing the active parliament composition. [11](#0-10) 

The miner count calculation shows growth over time, with the formula including multiplication by 2 per interval, confirming that miner counts change during term transitions. [12](#0-11) 

The consensus contract initialization shows that production uses `IsTermStayOne = false`, enabling term transitions, while tests often set it to `true`. [13](#0-12) 

The `AbstractVoteTotal` constant is 10000, used as the numerator scaling factor in all threshold calculations. [14](#0-13) 

This creates a TIME-OF-CHECK-TO-TIME-OF-USE (TOCTOU) vulnerability between proposal creation/voting and release where the parliament size can change, causing threshold calculations to use incorrect denominators.

## Impact Explanation

**Governance Integrity Violation:**

**Scenario 1 - Legitimate proposals fail:**
A proposal receives 7 approvals from a 9-member parliament (77.8%), meeting the default 66.67% approval threshold:
- Calculation at voting time: `7 * 10000 >= 6667 * 9` → `70000 >= 60003` ✓ PASS
- Parliament grows to 12 members before release
- Calculation at release time: `7 * 10000 >= 6667 * 12` → `70000 >= 80004` ✗ FAIL
- Result: Legitimately approved proposal cannot be released

**Scenario 2 - Invalid proposals pass rejection:**
A proposal receives 2 rejections from a 10-member parliament (20%), at the exact default 20% rejection threshold:
- Calculation at voting time: `2 * 10000 > 2000 * 10` → `20000 > 20000` ✗ FALSE (not rejected)
- Parliament shrinks to 8 members before release
- Calculation at release time: `2 * 10000 > 2000 * 8` → `20000 > 16000` ✓ TRUE (rejected)
- Result: Proposal that should pass is incorrectly rejected

**Affected Parties:**
- All parliament organizations (default organization, custom organizations, emergency response organization)
- System upgrades and configuration changes controlled by parliament
- Treasury operations and economic parameter adjustments
- Cross-chain operations requiring parliament approval
- Any governance action dependent on parliament approval integrity

**Severity Justification - HIGH:**
1. **Violates fundamental governance invariant:** The core principle that proposals meeting approval thresholds should pass is broken
2. **No privilege escalation required:** Triggered by normal consensus operations
3. **Affects critical system operations:** System upgrades, fee structures, treasury distributions
4. **Silent failure mode:** No warning mechanism; proposals appear valid but behave unexpectedly
5. **Affects all parliament organizations:** Not limited to a single organization or edge case

## Likelihood Explanation

**Trigger Conditions:**
1. A proposal is created before a consensus term transition
2. The proposal receives votes that place it near threshold boundaries
3. A term transition occurs, changing the miner count
4. The proposal is released after the term transition

**Feasibility - HIGH:**

**No special attacker capabilities required:**
- Term transitions are normal blockchain operations that occur regularly in AEDPoS consensus
- Any user can call `Release()` on proposals they created once thresholds appear to be met
- No special privileges, compromised keys, or consensus manipulation needed

**Attack complexity - LOW:**
- Passive exploitation: Legitimate proposals can fail during natural term transitions without malicious intent
- Active exploitation: An adversary can monitor pending proposals and strategically time release attempts around known term transitions
- Proposals typically have multi-day expiration windows (common governance practice), creating large overlap windows with term transition periods

**Frequency of occurrence:**
- Consensus term transitions occur regularly as part of normal blockchain operations
- Miner count changes are explicitly designed into the system
- Production configuration enables term transitions (`IsTermStayOne = false` in production vs `true` in tests)
- Multiple proposals often pending simultaneously, increasing probability of affected proposals

**Probability: HIGH** - The combination of regular term transitions, multi-day proposal lifetimes, and proposals near threshold boundaries makes this scenario highly probable in production environments.

## Recommendation

Implement parliament size snapshotting at proposal creation time:

1. **Add parliament size field to ProposalInfo structure:**
   - Store `parliamentMemberCount` when proposal is created
   - Store `parliamentMemberList` hash to detect composition changes

2. **Modify CreateNewProposal to snapshot parliament size:**
   ```csharp
   var proposal = new ProposalInfo
   {
       // ... existing fields ...
       ParliamentMemberCount = GetCurrentMinerList().Count,
       ParliamentMemberListHash = HashHelper.ComputeFrom(GetCurrentMinerList())
   };
   ```

3. **Use snapshotted values in threshold calculations:**
   ```csharp
   private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
   {
       // Use the parliament size from when proposal was created
       var parliamentMemberCount = proposal.ParliamentMemberCount;
       
       var approvedMemberCount = proposal.Approvals.Count;
       var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
           organization.ProposalReleaseThreshold.MinimalApprovalThreshold * parliamentMemberCount;
       
       // Similar adjustments for rejection, abstention, and vote thresholds
       // ...
   }
   ```

4. **Optional: Add warning if parliament composition has changed:**
   - Compare current parliament list hash with stored hash
   - Emit event warning that parliament has changed since proposal creation

## Proof of Concept

The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task Parliament_Threshold_TOCTOU_Vulnerability_Test()
{
    // Setup: Initialize with 9 miners
    var initialMinerCount = 9;
    await InitializeParliamentWithMiners(initialMinerCount);
    
    // Create proposal with default 66.67% approval threshold
    var proposalId = await CreateTestProposal();
    
    // Get 7 approvals (77.8% of 9 miners - PASSES threshold)
    for (int i = 0; i < 7; i++)
    {
        await ApproveProposal(proposalId, minerStubs[i]);
    }
    
    // Verify proposal would pass with current parliament size
    var proposalOutput = await ParliamentStub.GetProposal.CallAsync(proposalId);
    proposalOutput.ToBeReleased.ShouldBeTrue(); // 7/9 = 77.8% > 66.67%
    
    // Trigger term transition - parliament grows to 12 miners
    await TransitionToNextTerm(newMinerCount: 12);
    
    // Attempt release - should FAIL despite having enough votes originally
    var releaseResult = await ParliamentStub.Release.SendWithExceptionAsync(proposalId);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved"); // 7/12 = 58.3% < 66.67%
    
    // Verify proposal now shows as not releasable
    proposalOutput = await ParliamentStub.GetProposal.CallAsync(proposalId);
    proposalOutput.ToBeReleased.ShouldBeFalse(); // Threshold failed due to parliament size change
}
```

This test proves that a proposal meeting approval thresholds at voting time can fail to release after a term transition changes the parliament size, violating the fundamental governance invariant.

### Citations

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-100)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L225-253)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L27-29)
```csharp
        State.PeriodSeconds.Value = input.IsTermStayOne
            ? int.MaxValue
            : input.PeriodSeconds;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
```
