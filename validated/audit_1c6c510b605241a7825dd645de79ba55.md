# Audit Report

## Title
Parliament Governance Deadlock via Approval-Rejection Threshold Gap

## Summary
The Parliament contract's default voting thresholds contain a mathematical deadlock zone caused by asymmetric inequality operators and threshold values that allow proposals to become permanently stuck in pending state. With 66.67% approval required (inclusive `>=`) but only >20% rejection needed to block (strict `>`), a minority of 13.33%-20% miners can force deadlock by rejecting while remaining miners split between approval and abstention.

## Finding Description

The Parliament contract defines threshold constants that create an exploitable gap between approval and rejection requirements: [1](#0-0) 

The proposal rejection logic uses **strict inequality** (`>`) to check if a proposal should be blocked: [2](#0-1) 

Meanwhile, the approval logic uses **inclusive inequality** (`>=`) to check if sufficient approvals exist: [3](#0-2) 

**Root Cause:** The validation function explicitly allows threshold configurations where `MaximalRejectionThreshold + MinimalApprovalThreshold <= AbstractVoteTotal`: [4](#0-3) 

With default values: `2000 + 6667 = 8667 ≤ 10000`, creating a **13.33% gap** where proposals remain in limbo.

**Mathematical Proof with 100 miners:**
- To REJECT: `rejectionCount * 10000 > 200000` requires **21+ rejections**
- To APPROVE: `approvalCount * 10000 >= 666700` requires **67+ approvals**  
- With 20 rejections and 66 approvals: Neither condition is met → **Deadlock**

The release mechanism confirms proposals can only be released when thresholds are satisfied: [5](#0-4) 

**Why Existing Protections Fail:**
1. The validation function explicitly permits this configuration
2. `ClearProposal` only removes expired proposals - it doesn't resolve deadlock, just cleans up after failure
3. `ChangeOrganizationThreshold` requires the organization itself to call it, creating circular dependency (need to pass a proposal to fix the threshold that prevents proposals from passing)

## Impact Explanation

**Critical Governance Denial-of-Service:**

The default Parliament organization serves as the authority controller for system-wide governance functions across all core contracts: [6](#0-5) [7](#0-6) 

A deadlocked Parliament proposal prevents execution of:
- **Security fixes:** Emergency patches for vulnerabilities cannot be deployed
- **Parameter updates:** Economic parameters, fee adjustments, consensus settings
- **Contract upgrades:** Critical system contract improvements blocked
- **Cross-chain operations:** Inter-chain governance coordination halted
- **Configuration changes:** System-wide settings frozen

**Attack Surface:**
- Default organization (main governance body) uses vulnerable thresholds
- Custom organizations may inherit these defaults
- Emergency response organization has tighter thresholds (90%/10%) but is separate

**Severity: HIGH** - While not directly stealing funds, this enables minority censorship of critical governance actions, potentially preventing security fixes or necessary protocol adaptations that could lead to greater harm.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Control or coordination of 13-20 miners out of ~100 (13.33%-20%)
- Standard voting permissions via Parliament member status
- No special privileges needed beyond elected miner position

**Attack Complexity: LOW**
- Execute through normal `Reject()` method calls
- No technical sophistication required
- Can occur organically during contentious governance debates
- Natural vote splits may trigger deadlock unintentionally

**Feasibility Conditions:**
- Parliament members are elected miners (realistic precondition)
- Coordination among 13-20 miners is achievable for organized groups
- Controversial proposals naturally create vote fragmentation
- Detection is difficult - appears as legitimate disagreement until expiration

**Likelihood: MEDIUM-HIGH** - The attack is technically simple and coordination threshold is realistic for organized minority factions or can occur naturally in divisive governance scenarios.

## Recommendation

**Fix the threshold inequality asymmetry by using consistent comparison operators:**

1. **Option A (Preferred):** Use inclusive `>=` for both rejection and approval checks to eliminate the gap:
```csharp
// Change line 68-69 to use inclusive inequality
return rejectionMemberCount * AbstractVoteTotal >= 
       organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
```

2. **Option B:** Adjust default thresholds to eliminate the gap:
```csharp
// Set thresholds that sum to 100%
private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
private const int DefaultOrganizationMaximalRejectionThreshold = 3333; // Changed from 2000
```

3. **Option C:** Add validation to prevent deadlock zones:
```csharp
// In Validate() method, ensure no gap exists
Assert(proposalReleaseThreshold.MaximalRejectionThreshold + 
       proposalReleaseThreshold.MinimalApprovalThreshold >= AbstractVoteTotal,
       "Thresholds must not create deadlock zone");
```

**Recommended immediate action:** Implement Option A to use consistent inequality operators, combined with Option C to prevent future deadlock-prone configurations.

## Proof of Concept

```csharp
[Fact]
public async Task ParliamentDeadlock_20Rejections_66Approvals_StuckPending()
{
    // Setup: Get default Parliament organization with vulnerable thresholds
    var defaultOrg = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var orgInfo = await ParliamentContractStub.GetOrganization.CallAsync(defaultOrg);
    
    // Verify vulnerable thresholds: 6667 approval, 2000 rejection (13.33% gap)
    orgInfo.ProposalReleaseThreshold.MinimalApprovalThreshold.ShouldBe(6667);
    orgInfo.ProposalReleaseThreshold.MaximalRejectionThreshold.ShouldBe(2000);
    
    // Create proposal requiring Parliament approval
    var proposalId = await ParliamentContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        OrganizationAddress = defaultOrg,
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContract.Transfer),
        Params = new TransferInput { To = Address.FromPublicKey(SampleECKeyPairs.KeyPairs[0].PublicKey), Amount = 100 }.ToByteString(),
        ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(1)
    });
    
    // Get current miner list (assume 100 miners for this test)
    var minerList = await AEDPoSContractStub.GetCurrentMinerList.CallAsync(new Empty());
    var totalMiners = minerList.Pubkeys.Count;
    totalMiners.ShouldBe(100); // Test assumes 100 miners
    
    // Execute deadlock: 20 rejections, 66 approvals
    // 20 miners reject (20% - NOT enough to reject, needs >20%)
    for (int i = 0; i < 20; i++)
    {
        await GetParliamentContractTester(SampleECKeyPairs.KeyPairs[i]).Reject.SendAsync(proposalId.Output);
    }
    
    // 66 miners approve (66% - NOT enough to approve, needs >=66.67%)
    for (int i = 20; i < 86; i++)
    {
        await GetParliamentContractTester(SampleECKeyPairs.KeyPairs[i]).Approve.SendAsync(proposalId.Output);
    }
    
    // Remaining 14 miners abstain/don't vote (in the deadlock gap)
    
    // Attempt to release: Should fail with "Not approved"
    var releaseResult = await ParliamentContractStub.Release.SendWithExceptionAsync(proposalId.Output);
    releaseResult.TransactionResult.Error.ShouldContain("Not approved");
    
    // Verify proposal is stuck in pending state
    var proposalInfo = await ParliamentContractStub.GetProposal.CallAsync(proposalId.Output);
    proposalInfo.ToBeReleased.ShouldBeFalse(); // Cannot be released
    proposalInfo.RejectionCount.ShouldBe(20); // Not rejected (needs 21+)
    proposalInfo.ApprovalCount.ShouldBe(66); // Not approved (needs 67+)
    
    // Deadlock confirmed: Proposal remains pending indefinitely until expiration
    // Critical governance action is censored by 13.33% minority
}
```

## Notes

This vulnerability represents a **fundamental design flaw** in the Parliament voting threshold logic rather than an implementation bug. The asymmetric inequality operators (`>` vs `>=`) combined with threshold values that don't sum to 100% create a mathematical deadlock zone that can be exploited for governance denial-of-service.

The issue is particularly severe because:
1. It affects the **default Parliament organization** that controls system-wide governance
2. The **circular dependency** in `ChangeOrganizationThreshold` (requiring organization approval to change thresholds) prevents self-healing
3. Natural vote fragmentation in contentious proposals can trigger deadlock **unintentionally**
4. The validation logic explicitly **permits** this configuration, making it appear intentional

While proposals eventually expire and can be cleared, this does not constitute a resolution mechanism - it merely cleans up after the governance action has already failed. During the proposal lifetime, critical system updates remain blocked.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-9)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L142-155)
```csharp
    private bool Validate(Organization organization)
    {
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;

        return proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L59-71)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        RequireParliamentContractAddressSet();

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs (L280-293)
```csharp
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
            if (parliamentContractAddress == null)
                // Test environment.
                return new AuthorityInfo();

            State.ParliamentContract.Value = parliamentContractAddress;
        }

        var defaultOrganizationAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = defaultOrganizationAddress
        };
```
