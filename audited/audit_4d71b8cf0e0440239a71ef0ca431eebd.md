### Title
Parliament Governance Bypass via Empty Miner List from Consensus Contract

### Summary
The Parliament contract's threshold validation logic fails when the Consensus contract returns an empty miner list, allowing proposals to be released with zero votes. The mathematical checks in `IsReleaseThresholdReached` multiply against `parliamentMembers.Count`, which evaluates to zero when the miner list is empty, causing all threshold comparisons to incorrectly pass (0 >= 0).

### Finding Description

The Parliament contract retrieves the current miner list from the Consensus contract via `GetCurrentMinerList()` [1](#0-0) , which calls the Consensus contract's `GetCurrentMinerList` method [2](#0-1) .

The Consensus contract returns an empty `MinerList` when `TryToGetCurrentRoundInformation` fails (returns false), which occurs when `State.CurrentRoundNumber.Value == 0` or `State.Rounds[roundNumber].IsEmpty` [3](#0-2) .

When Parliament's threshold validation receives an empty miner list (`parliamentMembers.Count = 0`), the mathematical checks fail:

In `CheckEnoughVoteAndApprovals`: [4](#0-3) 
- `approvedMemberCount * 10000 >= MinimalApprovalThreshold * 0`
- This becomes `0 >= 0`, which is TRUE regardless of actual votes

In `IsVoteThresholdReached`: [5](#0-4) 
- `voteCount * 10000 >= MinimalVoteThreshold * 0`
- This becomes `0 >= 0`, which is TRUE

The `Release` method then executes proposals that pass these checks without validating that the miner list is non-empty [6](#0-5) .

### Impact Explanation

**Critical Governance Compromise**: Any proposal can be released with zero votes, completely bypassing the democratic voting mechanism. This allows:
- Unauthorized contract upgrades (including replacing the Consensus contract itself)
- Unauthorized fund transfers from Parliament-controlled addresses
- Arbitrary configuration changes across the system
- Complete subversion of the governance model

**Affected Parties**: All participants in the AElf governance system, as the Parliament contract controls critical system parameters and contract updates.

**Severity**: CRITICAL - Complete bypass of authorization controls in the primary governance mechanism.

### Likelihood Explanation

**Attack Prerequisites**:
1. Consensus contract must return an empty miner list, requiring either:
   - Deployment of a malicious Consensus contract (which paradoxically requires Parliament approval)
   - Critical bug in Consensus contract causing state corruption
   - Exploitation of uninitialized state (e.g., if Parliament is used before Consensus initialization)

**Complexity**: HIGH - The circular dependency (Parliament governs Consensus, but depends on Consensus) makes direct exploitation difficult. An attacker would need to first compromise the Consensus contract through legitimate governance, then use that to bypass future governance.

**Detection**: LOW - The empty miner list scenario would likely be detected quickly as it would break normal consensus operations, but the brief window could be exploited.

**Probability**: MEDIUM-LOW - While the mathematical vulnerability is certain, achieving the preconditions requires either prior system compromise or exploiting an initialization race condition.

### Recommendation

Add explicit validation in `GetCurrentMinerList()` to prevent empty miner lists:

```csharp
private List<Address> GetCurrentMinerList()
{
    RequireConsensusContractStateSet();
    var miner = State.ConsensusContract.GetCurrentMinerList.Call(new Empty());
    var members = miner.Pubkeys.Select(publicKey =>
        Address.FromPublicKey(publicKey.ToByteArray())).ToList();
    
    // Add validation
    Assert(members.Count > 0, "Miner list cannot be empty.");
    
    return members;
}
```

Additionally, add defensive checks in `IsReleaseThresholdReached()`:

```csharp
private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
{
    var parliamentMembers = GetCurrentMinerList();
    Assert(parliamentMembers.Count > 0, "Invalid parliament state: empty miner list.");
    // ... rest of logic
}
```

**Test Cases**:
1. Verify that `GetCurrentMinerList()` reverts when Consensus returns empty miner list
2. Verify that `Release()` fails when miner list becomes empty
3. Test initialization order to ensure Consensus is fully initialized before Parliament operations

### Proof of Concept

**Initial State**:
- Parliament contract deployed and initialized
- Consensus contract in a state where `State.CurrentRoundNumber.Value == 0` or round data is corrupted/empty
- At least one proposal exists in Parliament

**Attack Sequence**:
1. Attacker creates a proposal with arbitrary malicious transaction
2. Proposal receives zero votes (no approvals, rejections, or abstentions)
3. Attacker (as proposer) calls `Release(proposalId)`
4. `GetCurrentMinerList()` returns empty list from Consensus
5. `IsReleaseThresholdReached()` calculates: `0 * 10000 >= MinimalApprovalThreshold * 0` → TRUE
6. Proposal executes despite having zero votes

**Expected Result**: Release should fail due to insufficient votes
**Actual Result**: Release succeeds, executing the proposal transaction

**Success Condition**: Arbitrary proposal execution without meeting the configured approval threshold (e.g., 66.67% of miners)

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
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
