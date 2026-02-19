### Title
Quadratic Complexity in Vote Threshold Check Enables Governance DoS at Scale

### Summary
The `IsVoteThresholdReached` function uses `List<Address>.Contains()` within a LINQ predicate, creating O(P²) computational complexity where P is the parliament size. With no upper bound on `MaximumMinersCount` beyond requiring a positive value, a large parliament (e.g., 1000+ miners) would cause excessive gas consumption, preventing proposal releases and effectively DoS'ing the governance system.

### Finding Description
The vulnerability exists in the `IsVoteThresholdReached` helper function which counts votes meeting the minimum threshold: [1](#0-0) 

The function concatenates three vote lists (Abstentions, Approvals, Rejections) and counts how many are parliament members using `parliamentMembers.Contains()`. The `parliamentMembers` is returned as a `List<Address>`: [2](#0-1) 

Since `List<T>.Contains()` has O(n) complexity, and the Count predicate calls it for each vote (up to P votes where P = parliament size), the total complexity is O(P²).

The parliament size is determined by `GetCurrentMinerList()` from the consensus contract, which returns all miners in the current round without limit: [3](#0-2) 

The maximum miners count can be set via governance with only a positive value check and no upper bound: [4](#0-3) 

The default supposed miners count is 17, but can grow through auto-increase and governance-set maximum: [5](#0-4) 

### Impact Explanation
When parliament size grows large (e.g., 1000+ miners), the O(P²) complexity becomes problematic:
- At 1000 miners: ~1,000,000 address comparisons per vote threshold check
- At 10,000 miners: ~100,000,000 address comparisons

This causes:
1. **Governance DoS**: The `Release` function becomes unusable as it calls `IsReleaseThresholdReached` which requires vote threshold validation
2. **Operational Impact**: Critical governance proposals cannot be executed, breaking the upgrade and parameter adjustment mechanisms
3. **Chain Integrity**: Without functioning governance, the chain cannot respond to issues requiring parameter changes

The proposal release path is: [6](#0-5) 

All parliament members and proposers are affected, as proposals become unreleasable regardless of approval status.

### Likelihood Explanation
Likelihood is **LOW** due to multiple constraints:

1. **Governance Control**: Setting a high `MaximumMinersCount` requires parliament approval, meaning current miners must vote to enable their own potential DoS
2. **Growth Time**: Auto-increase adds only 2 miners per interval, making natural growth slow
3. **Resource Requirements**: Growing to 1000+ miners requires massive staking and voting across many candidates over extended time
4. **Economic Disincentive**: Large parliaments reduce individual miner rewards, naturally limiting growth

However, the vulnerability is real because:
- No code-enforced upper bound exists beyond `> 0`
- Governance could theoretically approve a high maximum (though unlikely)
- Over years, organic growth could reach problematic sizes

### Recommendation

**Immediate Fix:**
1. Replace `List<Address>` with `HashSet<Address>` in `GetCurrentMinerList()` return or convert before use, reducing Contains to O(1):
```csharp
private bool IsVoteThresholdReached(ProposalInfo proposal, Organization organization,
    ICollection<Address> parliamentMembers)
{
    var memberSet = new HashSet<Address>(parliamentMembers);
    var isVoteThresholdReached =
        proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
            .Count(memberSet.Contains) * AbstractVoteTotal >=
        organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
    return isVoteThresholdReached;
}
```

**Additional Hardening:**
2. Add upper bound validation in `SetMaximumMinersCount`:
```csharp
Assert(input.Value > 0 && input.Value <= 1000, "Invalid max miners count.");
```

3. Add gas cost checks before vote threshold computation for very large parliaments

**Test Cases:**
- Test vote threshold calculation with 100, 500, 1000 parliament members
- Verify proposal release succeeds within gas limits
- Test that MaximumMinersCount cannot be set above reasonable bounds

### Proof of Concept

**Initial State:**
- Parliament contract initialized with default configuration
- Consensus contract with default 17 miners

**Attack Steps:**
1. Through governance compromise or legitimate proposal, set `MaximumMinersCount` to 5000
2. Wait for election cycles and miner auto-increase to grow parliament to 1000+ members (requires months/years and significant staking)
3. Create any parliament proposal with valid parameters
4. Have sufficient miners vote (Approve/Reject/Abstain) to meet threshold
5. Proposer calls `Release(proposalId)`

**Expected Result:**
Proposal should be released and executed if thresholds met

**Actual Result:**
Transaction fails or consumes excessive gas due to:
- 1000+ iterations through votes
- Each calling `List<Address>.Contains()` checking against 1000+ members  
- Total: ~1,000,000 address comparison operations
- Causes transaction to exceed gas limits or time out

**Success Condition:**
Governance becomes unable to release proposals, demonstrated by Release transaction failures or excessive gas consumption beyond practical limits.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
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
