### Title
Parliament Proposal Vote Count Miscalculation Due to Dynamic Miner List Retrieval

### Summary
The `IsReleaseThresholdReached()` function retrieves the current miner list at validation time rather than using the miner list from when votes were cast. When the parliament member list changes between voting and proposal release (during term transitions), votes from former members are silently ignored, causing vote threshold calculations to fail incorrectly and enabling governance manipulation through timing attacks.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The function fetches the parliament member list dynamically on each invocation via `GetCurrentMinerList()`, which makes a cross-contract call to the consensus contract. [2](#0-1) 

This current member list is then used to filter stored votes in the validation checks. For example, in rejection validation, only votes from current members are counted: [3](#0-2) 

The same filtering occurs for abstentions and approvals: [4](#0-3) [5](#0-4) 

**Why Protections Fail:**
The miner list changes during term transitions in the consensus contract, which occur every 7 days by default (604800 seconds). [6](#0-5) 

Meanwhile, proposals have a default expiration of 72 hours (259200 seconds), creating a significant overlap window where proposals can span term boundaries. When `Release()` is called, it uses the validation function with the new member list: [7](#0-6) 

**Exploitation Path:**
1. Attacker creates a proposal near a term transition
2. Proposal gets approved by current parliament members (threshold met)
3. Term transition occurs, replacing some parliament members
4. When `Release()` is called, `IsReleaseThresholdReached()` fetches the NEW miner list
5. Votes from former members are not counted (they fail `parliamentMembers.Contains` check)
6. Proposal may now fail threshold validation despite having sufficient votes when cast

### Impact Explanation

**Governance Manipulation:**
- Legitimate votes from valid parliament members at voting time are silently discarded
- Proposal outcomes become timing-dependent rather than vote-dependent
- Creates unpredictability in governance decisions

**Attack Scenarios:**
1. **Blocking Valid Proposals:** An adversary can delay releasing an approved proposal until a term change invalidates enough approval votes, preventing execution of legitimate governance actions
2. **Forcing Invalid Proposals:** An adversary can wait for opposing members to be replaced, then release a previously rejected/blocked proposal
3. **Threshold Gaming:** Vote counts can artificially decrease when the denominator (total members) remains the same but numerator (counted votes) drops

**Affected Parties:**
- All parliament members whose votes are invalidated after replacement
- Proposal creators whose proposals fail despite meeting thresholds
- The entire governance system's integrity and trustworthiness

**Severity Justification:**
High severity due to direct governance manipulation capability affecting critical system decisions including contract upgrades, parameter changes, and fund management.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires ability to create proposals or influence timing of proposal release
- Requires knowledge of term transition schedule (predictable, every 7 days)
- No special privileges needed beyond being an authorized proposer

**Attack Complexity:**
- Medium complexity: requires timing coordination but no technical sophistication
- Term transitions are deterministic and predictable
- 72-hour proposal expiration window provides ample opportunity to span term boundaries

**Feasibility Conditions:**
- Term changes every ~7 days are regular network events
- Proposals with 72-hour expiration can easily span term boundaries
- No mechanism exists to lock member list at proposal creation
- No re-validation or re-voting occurs after member list changes

**Detection Constraints:**
- Vote discarding is silent with no events or notifications
- Appears as legitimate threshold validation failure
- Difficult to distinguish from genuine vote insufficiency

**Probability Assessment:**
Medium-High: The window is constrained but predictable, and exploitation requires only timing coordination. The attack is economically rational for high-value governance proposals affecting funds or critical parameters.

### Recommendation

**Code-Level Mitigation:**

1. **Snapshot Member List at Proposal Creation:**
   Store the parliament member list hash or full list in the `ProposalInfo` structure when proposals are created. Use this snapshot for all threshold calculations.

2. **Add Member List Validation:**
   In `IsReleaseThresholdReached()`, add a check:
   ```csharp
   private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
   {
       var currentMembers = GetCurrentMinerList();
       var proposalCreationMembers = proposal.MemberListSnapshot; // Store at creation
       
       // Validate no significant divergence
       Assert(CalculateMemberOverlap(currentMembers, proposalCreationMembers) >= MinimumOverlapThreshold,
              "Member list changed significantly, proposal must be recreated");
       
       // Continue with validation using creation-time members...
   }
   ```

3. **Alternative - Use Stored Member Count:**
   Store the member count at proposal creation time and use it as the denominator in threshold calculations instead of `parliamentMembers.Count`.

**Invariant Checks:**
- Member list used for threshold calculation must be consistent with member list when votes were cast
- Vote count denominator must match the member count when proposal was created or votes were cast
- Emit events when member list changes affect active proposals

**Test Cases:**
- Test proposal spanning term transition with member replacements
- Verify votes from former members are either counted or proposal is invalidated
- Test threshold calculations with member list changes
- Test edge case where all approving members are replaced

### Proof of Concept

**Initial State:**
- Parliament members: [Miner_A, Miner_B, Miner_C, Miner_D, Miner_E] (5 members)
- Organization threshold: MinimalApprovalThreshold = 6667 (66.67%)
- Required approvals: 6667 * 5 / 10000 = 3.33, so need 4 approvals

**Transaction Steps:**

1. **T0 - Create Proposal (Day 6.5 of current term):**
   - Create proposal with 72-hour expiration
   - Proposal ID: P1

2. **T1 - Cast Votes:**
   - Miner_A: Approve P1
   - Miner_B: Approve P1  
   - Miner_C: Approve P1
   - Miner_D: Approve P1
   - Result: 4 approvals, threshold met (4 * 10000 >= 6667 * 5 = 40000 >= 33335) ✓

3. **T2 - Term Transition Occurs (Day 7.0):**
   - New miner list: [Miner_A, Miner_B, Miner_X, Miner_Y, Miner_Z]
   - Miner_C and Miner_D replaced

4. **T3 - Attempt Release (Day 7.5, within 72h expiration):**
   - Call `Release(P1)`
   - `IsReleaseThresholdReached()` fetches NEW member list
   - Counts approvals: Only Miner_A and Miner_B are in current list
   - Result: 2 approvals counted (2 * 10000 >= 6667 * 5 = 20000 >= 33335) ✗

**Expected vs Actual Result:**
- **Expected:** Proposal releases successfully (had 4/5 approvals when voted)
- **Actual:** Proposal fails validation (only 2/5 approvals counted with new member list)

**Success Condition:**
Demonstrate that a proposal meeting thresholds at voting time fails release validation after term transition due to vote count miscalculation from dynamic member list retrieval.

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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-144)
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
```
