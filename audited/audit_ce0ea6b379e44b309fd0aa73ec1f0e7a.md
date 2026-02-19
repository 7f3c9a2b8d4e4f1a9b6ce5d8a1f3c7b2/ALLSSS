### Title
Governance Deadlock via Participation Suppression Attack on 75% Vote Threshold

### Summary
The Parliament contract's 75% participation requirement (MinimalVoteThreshold=7500) is vulnerable to governance deadlock attacks. Attackers can prevent proposal passage indefinitely by suppressing 25% of miner participation through DOS, network partitioning, or collusion, as offline miners remain in the voting denominator for up to 3 days before removal, while proposals expire in the same timeframe.

### Finding Description

The Parliament contract requires 75% of current miners to vote (approve, reject, or abstain) before a proposal can be released. [1](#0-0) 

The critical vulnerability exists in the threshold calculation logic where the current miner list is dynamically retrieved at release time: [2](#0-1) 

The miner list is obtained from the consensus contract: [3](#0-2) 

The proposal release check enforces this threshold: [4](#0-3) 

**Root Cause:** Miners who are offline, partitioned, or DOS'd remain in the miner list (and thus the voting denominator) for up to 3 days before being detected as "evil": [5](#0-4) 

Meanwhile, proposals expire after 72 hours: [6](#0-5) 

**Why Protections Fail:**

1. The Emergency Response Organization has a **higher** 90% threshold, making it even harder to use: [7](#0-6) 

2. Evil miner detection occurs during round processing but only marks them after 3 days of missed slots: [8](#0-7) 

3. The threshold can only be changed via ChangeOrganizationThreshold, which requires a successful proposal first: [9](#0-8) 

4. Expired proposals are simply cleared and must be recreated, but face the same threshold problem: [10](#0-9) 

### Impact Explanation

**Governance Deadlock:** Critical system proposals cannot pass, preventing contract upgrades, parameter changes, security patches, and emergency responses. This affects the entire network and all users.

**Concrete Attack Scenario:**
- Attacker identifies a critical proposal requiring passage
- Attacker DOS's or network-partitions 25% of miners (4-5 out of 17 default miners)
- Proposal cannot reach 75% threshold because offline miners count in denominator
- Proposal expires after 72 hours
- New proposal faces same attack; cycle repeats indefinitely

**Self-Reinforcing:** To lower the threshold and escape the deadlock, you must pass a proposal to execute ChangeOrganizationThreshold, but passing proposals is blocked by the threshold itself.

**Severity Justification:** HIGH - Complete governance paralysis prevents critical system operations, security responses, and evolution. No automated recovery mechanism exists.

### Likelihood Explanation

**Attacker Capabilities Required:**
- **Network Partitioning:** Deploy network-layer attacks to isolate 25% of miners (4-5 nodes)
- **DOS Attack:** Target 25% of miner nodes with sustained DOS for 72+ hours
- **Social Engineering/Collusion:** Convince 25% of miners to abstain from voting

**Attack Complexity:** MEDIUM
- Network partitions occur naturally in distributed systems
- DOS attacks against 4-5 specific nodes are feasible
- Miner collusion requires social coordination but only 25% threshold

**Feasibility Conditions:**
- Known miner IP addresses/identities (public in DPoS systems)
- Network access to launch DOS or create partitions
- Proposal visibility to time the attack

**Detection/Operational Constraints:**
- Attack is passive (preventing votes) and may appear as network issues
- Difficult to distinguish from legitimate network problems
- 3-day window before automatic miner replacement kicks in
- Defenders cannot quickly adjust threshold without passing a proposal

**Probability Assessment:** MEDIUM-HIGH - The 25% threshold is low enough to be achievable through various attack vectors, and the 3-day persistence requirement aligns with proposal expiration, making the attack timing practical.

### Recommendation

**Immediate Mitigations:**

1. **Implement Adaptive Threshold Logic:**
```
// In IsVoteThresholdReached method
var activeMinerCount = GetActiveMinerCount(); // Miners who voted in last N rounds
var thresholdBase = activeMinerCount > 0 ? activeMinerCount : parliamentMembers.Count;
var isVoteThresholdReached = totalVotes * AbstractVoteTotal >= 
    organization.ProposalReleaseThreshold.MinimalVoteThreshold * thresholdBase;
```

2. **Add Emergency Bypass Mechanism:**
Create a time-based threshold reduction where if a proposal has been pending for >48 hours with >50% participation, allow a lower threshold (e.g., 66% of active voters instead of 75% of all miners).

3. **Separate Emergency Organization Threshold:**
Lower the Emergency Response Organization threshold to 66% instead of 90%, or make it count only active miners who participated in recent rounds.

4. **Add Proposal Extension:**
Allow proposals to be extended beyond 72 hours if they show >50% participation but haven't reached threshold, giving time for network issues to resolve.

**Invariant Checks to Add:**
- Assert that voting threshold denominator uses only miners active in last X rounds
- Add monitoring for proposals approaching expiration with high participation but insufficient threshold
- Track miner voting participation rates and alert when dropping below threshold requirements

**Test Cases:**
- Simulate network partition with 25% miners offline and verify proposals can still pass
- Test proposal passage when 4 of 17 miners are marked as evil but not yet replaced
- Verify emergency organization can function during partial miner unavailability
- Test threshold adjustment mechanism under various participation scenarios

### Proof of Concept

**Initial State:**
- 17 miners in the current miner list
- Default organization with MinimalVoteThreshold = 7500 (75%)
- Critical proposal created (e.g., contract upgrade)

**Attack Execution:**

1. **T=0 hours:** Attacker identifies proposal ProposalId X requiring passage

2. **T=0 hours:** Attacker launches DOS attack against 5 miners (29% of 17), preventing them from submitting vote transactions

3. **T=0-72 hours:** Honest miners vote:
   - 12 miners vote (approve/reject/abstain)
   - Current calculation: `12 * 10000 / 17 = 7058 < 7500` ❌
   - Threshold NOT reached despite 71% of miners voting

4. **T=72 hours:** Proposal expires via expiration check: [11](#0-10) 

5. **T=72 hours:** Anyone clears expired proposal: [10](#0-9) 

6. **T=72+ hours:** New proposal created, attack repeats

**Expected vs Actual:**
- **Expected:** Evil miner detection should remove DOS'd miners from voting pool within proposal lifetime
- **Actual:** Evil miners require 4320 missed time slots (3 days) for detection, equal to proposal expiration period
- **Result:** Proposal expires before offline miners are removed from denominator

**Success Condition:** Attacker successfully blocks proposal passage indefinitely by maintaining DOS on 25% of miners, demonstrating governance deadlock vulnerability.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L8-8)
```csharp
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L94-101)
```csharp
    private bool IsVoteThresholdReached(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
        return isVoteThresholdReached;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L177-180)
```csharp
    private bool CheckProposalNotExpired(ProposalInfo proposal)
    {
        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L314-330)
```csharp
    private void CreateEmergencyResponseOrganization()
    {
        var createOrganizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 9000,
                MinimalVoteThreshold = 9000,
                MaximalAbstentionThreshold = 1000,
                MaximalRejectionThreshold = 1000
            },
            ProposerAuthorityRequired = false,
            ParliamentMemberProposingAllowed = true
        };

        State.EmergencyResponseOrganizationAddress.Value = CreateOrganization(createOrganizationInput);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L5-5)
```csharp
    public const int ContractProposalExpirationTimePeriod = 259200; // 60 * 60 * 72
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L147-159)
```csharp
    public override Empty ChangeOrganizationThreshold(ProposalReleaseThreshold input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationThresholdChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerReleaseThreshold = input
        });
        return new Empty();
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
