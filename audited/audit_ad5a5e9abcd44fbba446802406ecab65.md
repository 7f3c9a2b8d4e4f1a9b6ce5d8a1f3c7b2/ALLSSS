### Title
Emergency Organization Can Remove Candidates Without Evidence Validation

### Summary
The `RemoveEvilNode` function authorized by `EmergencyResponseOrganizationAddress` lacks any technical validation or evidence requirements to prove candidate misbehavior. While the consensus contract automatically detects evil miners based on objective criteria (≥4320 missed time slots), the emergency organization can arbitrarily remove any candidate with only a 90% governance vote, bypassing evidence-based validation entirely.

### Finding Description

The `EmergencyResponseOrganizationAddress` state variable [1](#0-0)  is used to authorize emergency operations in the Election contract.

The `RemoveEvilNode` function [2](#0-1)  only validates:
1. Caller is the emergency organization address (line 338)
2. Target is a candidate or initial miner (lines 341-343)  
3. Target is not already banned (line 344)

**Root Cause**: The function calls `UpdateCandidateInformation` with `IsEvilNode=true` without providing any evidence fields (`recently_missed_time_slots`, `recently_produced_blocks`), which are defined in the protobuf structure [3](#0-2) .

**Why Protections Fail**: The emergency organization is created with high voting thresholds [4](#0-3)  (90% approval, 90% participation, max 10% rejection/abstention), but Parliament's proposal release mechanism [5](#0-4)  performs no validation of proposal parameters or evidence—it only checks voting thresholds are met.

**Comparison with Evidence-Based Path**: The consensus contract automatically detects evil miners through objective on-chain evidence [6](#0-5) , requiring `MissedTimeSlots >= TolerableMissedTimeSlotsCount` (4320 slots = 3 days) [7](#0-6) . The emergency path bypasses this entirely.

### Impact Explanation

**Direct Impact**:
- Legitimate candidates can be permanently banned from the candidate pool
- Removed nodes lose all future mining rewards, profit distributions, and treasury allocations
- The node's staked collateral and voting weight are eliminated without cause

**Governance Impact**:
- Bypasses the evidence-based evil node detection system designed by the protocol
- Enables political/economic attacks where a supermajority removes competitors
- Undermines trust in the fairness of the election system

**Who is Affected**:
- Individual candidates who can be removed arbitrarily
- Token holders who voted for removed candidates (their voting power is nullified)
- Network security (fewer legitimate candidates reduces decentralization)

**Severity Justification**: Medium severity because while impact is significant (permanent ban, loss of all benefits), the likelihood requires extraordinary collusion (90% of parliament members), which provides some practical limitation.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Control or influence 90% of current parliament members (current miners)
- Ability to create and pass a governance proposal through the emergency organization

**Attack Complexity**:
- Step 1: Coordinate with 90% of miners to approve malicious proposal
- Step 2: Create proposal calling `RemoveEvilNode` with target candidate pubkey
- Step 3: Obtain 90% approval votes from parliament members
- Step 4: Release and execute the proposal

**Feasibility Conditions**:
- Parliament must be sufficiently concentrated or colluding (e.g., cartel behavior, political alignment against competitor)
- No external evidence auditing or challenge period exists
- Decision is irreversible once executed

**Detection Constraints**: 
- The `EvilMinerDetected` event is fired [8](#0-7) , but provides no evidence trail
- Off-chain observers cannot verify if removal was legitimate

**Probability Reasoning**: While 90% threshold is high, it's achievable in scenarios of:
- Mining centralization (few entities control multiple nodes)
- Coordinated economic attack (oligopoly removing newcomer)
- Political pressure in consortium/permissioned deployments

### Recommendation

**Code-Level Mitigation**:

Add evidence validation to `RemoveEvilNode`:
```csharp
public override Empty RemoveEvilNode(RemoveEvilNodeInput input)
{
    Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
    
    // NEW: Require evidence of misbehavior
    Assert(input.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount || 
           input.Evidence != null, "Insufficient evidence for evil node removal.");
    
    // Existing validation
    Assert(State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Pubkey) ||
           State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Pubkey),
           "Cannot remove normal node.");
    Assert(!State.BannedPubkeyMap[input.Pubkey], $"{input.Pubkey} already banned.");
    
    UpdateCandidateInformation(new UpdateCandidateInformationInput
    {
        Pubkey = input.Pubkey,
        IsEvilNode = true,
        RecentlyMissedTimeSlots = input.MissedTimeSlots  // NEW: Include evidence
    });
    return new Empty();
}
```

**Invariant Checks**:
1. Emergency removal must include quantifiable evidence (missed slots, malicious behavior proof)
2. Evidence must meet or exceed the automatic detection threshold
3. Evidence data should be logged in the event for transparency

**Additional Recommendations**:
- Implement a challenge period allowing the accused candidate to dispute
- Add evidence hash to the proposal parameters for off-chain verification
- Consider requiring consensus contract co-signature for emergency removals
- Add governance parameter for minimum evidence threshold

### Proof of Concept

**Initial State**:
- Emergency Response Organization created via Parliament [9](#0-8) 
- Target candidate "CandidateX" is a legitimate node with good performance
- 90% of parliament members are colluding miners

**Attack Steps**:
1. Colluding miners create proposal targeting CandidateX:
   - `ToAddress`: Election contract address
   - `ContractMethodName`: "RemoveEvilNode"  
   - `Params`: StringValue { Value = "CandidateX" }
   - `OrganizationAddress`: Emergency organization address

2. 90% of parliament members vote to approve the proposal

3. Proposer calls `Release()` on the approved proposal

4. Parliament contract executes `RemoveEvilNode("CandidateX")` via virtual inline call

5. Election contract bans CandidateX permanently

**Expected vs Actual Result**:
- **Expected**: Removal should require proof of ≥4320 missed time slots or other objective evidence
- **Actual**: CandidateX is banned immediately with zero evidence, only governance votes

**Success Condition**: 
CandidateX's pubkey appears in `BannedPubkeyMap` [10](#0-9)  and is removed from `Candidates` list [11](#0-10)  despite having no actual consensus violations or missed time slots recorded on-chain.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L90-90)
```csharp
    public SingletonState<Address> EmergencyResponseOrganizationAddress { get; set; }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L96-96)
```csharp
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L106-106)
```csharp
            Context.Fire(new EvilMinerDetected { Pubkey = input.Pubkey });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L108-110)
```csharp
            var candidates = State.Candidates.Value;
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-351)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
    }
```

**File:** protobuf/election_contract.proto (L265-274)
```text
message UpdateCandidateInformationInput {
    // The candidate public key.
    string pubkey = 1;
    // The number of blocks recently produced.
    int64 recently_produced_blocks = 2;
    // The number of time slots recently missed.
    int64 recently_missed_time_slots = 3;
    // Is it a evil node. If true will remove the candidate.
    bool is_evil_node = 4;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```
