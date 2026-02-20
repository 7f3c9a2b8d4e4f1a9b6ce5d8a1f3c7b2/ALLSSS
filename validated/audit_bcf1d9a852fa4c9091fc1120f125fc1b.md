# Audit Report

## Title
Parliament Governance Deadlock via Approval-Rejection Threshold Gap

## Summary
The Parliament contract's default voting thresholds create a mathematical deadlock zone where proposals cannot pass or fail, enabling minority censorship of critical governance actions. The asymmetric inequality operators combined with threshold values allow 20 rejections to block rejection and 66 approvals to block approval simultaneously, leaving proposals permanently stuck.

## Finding Description

The Parliament contract defines default threshold constants that create an exploitable gap between approval and rejection requirements. [1](#0-0) 

The proposal rejection logic uses **strict inequality** (`>`) to determine if a proposal should be blocked. [2](#0-1)  This requires `rejectionCount * 10000 > MaximalRejectionThreshold * memberCount`, meaning with 100 miners and threshold 2000, it requires **21 or more rejections** to block a proposal.

Meanwhile, the approval logic uses **inclusive inequality** (`>=`) to check if sufficient approvals exist. [3](#0-2)  This requires `approvalCount * 10000 >= MinimalApprovalThreshold * memberCount`, meaning with 100 miners and threshold 6667, it requires **67 or more approvals** to pass a proposal.

**Root Cause:** The validation function explicitly allows threshold configurations where the sum of rejection and approval thresholds is less than the total vote weight. [4](#0-3)  With default values: `2000 + 6667 = 8667 ≤ 10000`, creating a **13.33% gap** where proposals remain in limbo.

The release mechanism confirms proposals can only be released when rejection checks pass and approval thresholds are met. [5](#0-4) 

**Why Existing Protections Fail:**

1. The validation function explicitly permits this configuration as valid
2. The `ClearProposal` method only removes expired proposals after they fail [6](#0-5)  - it doesn't resolve deadlock, just cleans up afterward
3. `ChangeOrganizationThreshold` requires the organization address itself as sender [7](#0-6) , creating circular dependency (need to pass a proposal to fix the threshold that prevents proposals from passing)

## Impact Explanation

**Critical Governance Denial-of-Service:**

The Parliament's DefaultOrganizationAddress serves as the authority controller across core system contracts including Configuration [8](#0-7) , MultiToken [9](#0-8) , Consensus [10](#0-9) , and TokenConverter [11](#0-10) .

A deadlocked Parliament proposal prevents execution of:
- **Security fixes:** Emergency patches for vulnerabilities cannot be deployed
- **Parameter updates:** Economic parameters, fee adjustments, consensus settings
- **Contract upgrades:** Critical system contract improvements blocked
- **Cross-chain operations:** Inter-chain governance coordination halted
- **Configuration changes:** System-wide settings frozen

**Severity: HIGH** - While not directly stealing funds, this enables minority censorship of critical governance actions, potentially preventing security fixes or necessary protocol adaptations that could lead to greater harm.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Control or coordination of 13-20 miners out of ~100 (13.33%-20%)
- Standard voting permissions via Parliament member status [12](#0-11) 
- No special privileges needed beyond elected miner position

**Attack Complexity: LOW**
- Execute through normal `Reject()` method calls using public interface
- No technical sophistication required
- Can occur organically during contentious governance debates without malicious intent
- Natural vote splits may trigger deadlock unintentionally

**Feasibility Conditions:**
- Parliament members are current miners (realistic precondition)
- Coordination among 13-20 miners is achievable for organized minority factions
- Controversial proposals naturally create vote fragmentation
- Detection is difficult - appears as legitimate disagreement until expiration

**Likelihood: MEDIUM-HIGH** - The attack is technically simple and the coordination threshold is realistic for organized minority factions or can occur naturally in divisive governance scenarios.

## Recommendation

Modify the validation function to ensure no deadlock zone exists by requiring:

```
MaximalRejectionThreshold + MinimalApprovalThreshold > AbstractVoteTotal
```

This ensures that if a proposal doesn't have enough rejections to block it, it will have enough approvals to pass it (or vice versa), eliminating the deadlock zone.

Additionally, consider:
1. Using consistent inequality operators (both `>` or both `>=`)
2. Implementing a "majority of votes cast" mechanism as fallback
3. Allowing emergency threshold adjustments through a separate emergency governance path
4. Adding explicit deadlock detection and resolution in the `GetProposal` view method

## Proof of Concept

```csharp
// Test scenario with 100 miners
// 20 miners reject (insufficient: need 21+ to block)
// 66 miners approve (insufficient: need 67+ to pass)
// 14 miners abstain or don't vote
// Result: Proposal stuck in deadlock until expiration

[Fact]
public async Task ParliamentProposal_Deadlock_Test()
{
    // Setup: Create default organization with vulnerable thresholds
    var organization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Create a proposal
    var proposalId = await CreateProposalAsync(organization);
    
    // Get current 100 miners
    var miners = await GetCurrentMinersAsync();
    
    // 20 miners reject (20 * 10000 = 200000, NOT > 200000)
    for (int i = 0; i < 20; i++)
    {
        await GetParliamentContractStub(miners[i]).Reject.SendAsync(proposalId);
    }
    
    // 66 miners approve (66 * 10000 = 660000, NOT >= 666700)
    for (int i = 20; i < 86; i++)
    {
        await GetParliamentContractStub(miners[i]).Approve.SendAsync(proposalId);
    }
    
    // Try to release - should fail
    var result = await ParliamentContractStub.Release.SendWithExceptionAsync(proposalId);
    
    // Verify proposal is stuck in deadlock
    var proposal = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeFalse(); // Cannot be released
    proposal.RejectionCount.ShouldBe(20); // Not enough to reject
    proposal.ApprovalCount.ShouldBe(66); // Not enough to approve
    
    // Deadlock confirmed: proposal stuck until expiration
}
```

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-9)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L83-86)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L151-154)
```csharp
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L96-112)
```csharp
    public override Empty Reject(Hash input)
    {
        var parliamentMemberAddress = GetAndCheckActualParliamentMemberAddress();
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedByMember(proposal, parliamentMemberAddress);
        proposal.Rejections.Add(parliamentMemberAddress);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = parliamentMemberAddress,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Reject),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L147-160)
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

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L14-18)
```csharp
        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L288-293)
```csharp
        var defaultOrganizationAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = defaultOrganizationAddress
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L36-42)
```csharp
        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MaximumMinersCountController.Value = defaultAuthority;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L411-415)
```csharp
        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
```
