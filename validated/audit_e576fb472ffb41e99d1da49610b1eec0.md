# Audit Report

## Title
Permanent Authority Lockout via MethodFeeController Change to Inaccessible Organization

## Summary
The `ChangeMethodFeeController()` function allows changing the method fee controller to a Parliament organization with impossible-to-achieve voting thresholds (e.g., 100% approval required). Once changed, the system becomes permanently locked from any future fee updates or controller changes, as there is no recovery mechanism and the only way to modify the controller requires executing a proposal through the now-inaccessible organization.

## Finding Description

The vulnerability exists in the `ChangeMethodFeeController()` implementation which validates only that the sender is the current controller and that the new organization exists, but does **not** validate whether the new organization has achievable voting thresholds. [1](#0-0) 

The Parliament contract's validation logic explicitly permits creating organizations with extreme thresholds. The `Validate` method allows `MinimalApprovalThreshold` up to and including 10000 (representing 100%). [2](#0-1) [3](#0-2) 

Test cases confirm that organizations with `MinimalApprovalThreshold = 10000` are explicitly permitted and successfully created: [4](#0-3) 

When a proposal is released, it executes with the organization's virtual address as the sender via `SendVirtualInlineBySystemContract`: [5](#0-4) 

The critical issue is that with a 100% approval threshold, the approval check becomes mathematically impossible if any single miner is unavailable: [6](#0-5) 

The formula `approvedMemberCount * 10000 >= 10000 * parliamentMembers.Count` requires ALL miners to approve when threshold is 10000. If any single miner is offline, compromised, or refuses to vote, the proposal can never reach the release threshold.

The default initialization only sets the controller if it's null, providing no recovery path: [7](#0-6) 

Once the `MethodFeeController` is set to an inaccessible organization, it cannot be reset to default because the early return on line 93 prevents re-initialization. There is no emergency override mechanism - the EmergencyResponseOrganization only has authority over candidate information updates, not MethodFeeController: [8](#0-7) 

## Impact Explanation

**Critical Governance Failure with System-Wide Effect:**

1. **Permanent Loss of Fee Governance**: Once locked, the protocol permanently loses the ability to adjust method fees. This affects ALL system contracts implementing ACS1, including Token, Treasury, Consensus, Election, Parliament, Profit, CrossChain, Economic, Configuration, Referendum, TokenConverter, TokenHolder, and Vote contracts.

2. **Economic Rigidity**: The blockchain cannot adapt transaction fees to changing network conditions, token valuations, or spam attacks. Fees remain frozen at potentially inappropriate levels indefinitely.

3. **No Recovery Mechanism**: There is no bypass, emergency override, or reset function. The EmergencyResponseOrganization has no special authority over MethodFeeController. The `RequiredMethodFeeControllerSet` function only initializes if the value is null, so once set to an inaccessible organization, it cannot be reset.

4. **Critical Invariant Violation**: Violates the fundamental governance invariant that "method-fee provider authority must remain accessible for system adaptation." This breaks the protocol's ability to evolve and respond to network conditions.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Capabilities Required:**
- Must be able to create Parliament organizations (requires being a miner or whitelisted proposer)
- Must be able to propose to the default Parliament organization (same requirement)  
- Must obtain 2/3 approval from miners to pass the governance proposal [9](#0-8) 

**Attack Complexity: Low**
1. Create organization with MinimalApprovalThreshold=10000 (single transaction)
2. Create proposal to change MethodFeeController to this organization (single transaction)
3. Obtain governance approval through normal voting (may appear as legitimate governance change)
4. Release approved proposal (single transaction)

**High Feasibility:**
- The attack could be executed **accidentally** by well-intentioned governance participants who don't understand the irreversibility
- Could be executed maliciously by a compromised miner
- No technical barriers prevent execution once governance approval is obtained
- The dangerous threshold configuration (100% approval) might not be obvious to voters reviewing the proposal

**Economic Rationality:**
- Attack cost is minimal (only transaction fees)
- Could be motivated by griefing, ransom demands, or competitive sabotage
- Accidental execution through governance error is realistic given complexity of threshold implications

## Recommendation

Add validation to `ChangeMethodFeeController()` to prevent setting controllers to organizations with unreachable thresholds:

1. **Validate Threshold Achievability**: Before accepting a new MethodFeeController, verify that the organization's `MinimalApprovalThreshold` is less than 10000 (100%) to ensure proposals can pass even if one miner is unavailable.

2. **Add Emergency Override**: Implement a special recovery mechanism (e.g., via EmergencyResponseOrganization or consensus contract) that can reset MethodFeeController in extreme circumstances.

3. **Implement Threshold Warnings**: Add explicit checks that warn or reject organizations where `MinimalApprovalThreshold >= MinimalVoteThreshold * 0.95` (requires >95% participation).

Suggested fix for `ChangeMethodFeeController`:
```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");
    
    // NEW: Validate threshold is achievable
    var organization = GetOrganization(input.OwnerAddress);
    Assert(organization.ProposalReleaseThreshold.MinimalApprovalThreshold < 10000,
           "Organization threshold requires 100% approval - would cause permanent lockout.");
    
    State.MethodFeeController.Value = input;
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task PermanentLockout_Via_InaccessibleOrganization_Test()
{
    // Step 1: Create organization with 100% approval threshold (impossible to achieve)
    var impossibleOrgAddress = await ParliamentContractStub.CreateOrganization.SendAsync(
        new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 10000,  // 100% - requires ALL miners
                MinimalVoteThreshold = 10000,
                MaximalAbstentionThreshold = 0,
                MaximalRejectionThreshold = 0
            }
        });
    
    var impossibleOrg = Address.Parser.ParseFrom(impossibleOrgAddress.TransactionResult.ReturnValue);
    
    // Step 2: Get current controller (default Parliament org with 66.67% threshold)
    var currentController = await TokenContractStub.GetMethodFeeController.CallAsync(new Empty());
    
    // Step 3: Create proposal to change MethodFeeController to impossible org
    var proposalId = await CreateFeeProposalAsync(
        TokenContractAddress,
        currentController.OwnerAddress,
        nameof(TokenContractStub.ChangeMethodFeeController),
        new AuthorityInfo
        {
            OwnerAddress = impossibleOrg,
            ContractAddress = ParliamentContractAddress
        });
    
    // Step 4: Approve with 2/3 miners (passes default 66.67% threshold)
    await ApproveAsync(InitialMinersKeyPairs[0], proposalId);
    await ApproveAsync(InitialMinersKeyPairs[1], proposalId);
    await ApproveAsync(InitialMinersKeyPairs[2], proposalId);
    
    // Step 5: Release proposal - changes controller to impossible org
    var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 6: Verify controller is now the impossible organization
    var newController = await TokenContractStub.GetMethodFeeController.CallAsync(new Empty());
    newController.OwnerAddress.ShouldBe(impossibleOrg);
    
    // Step 7: Try to change it back - create proposal through impossible org
    var recoverProposalId = await ParliamentContractStub.CreateProposal.SendAsync(
        new CreateProposalInput
        {
            OrganizationAddress = impossibleOrg,
            ToAddress = TokenContractAddress,
            ContractMethodName = nameof(TokenContractStub.ChangeMethodFeeController),
            Params = new AuthorityInfo
            {
                OwnerAddress = currentController.OwnerAddress,
                ContractAddress = ParliamentContractAddress
            }.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
        });
    
    var recoverProposal = Hash.Parser.ParseFrom(recoverProposalId.TransactionResult.ReturnValue);
    
    // Step 8: Even with all 5 miners approving, can't reach 100% threshold if one abstains
    await ApproveAsync(InitialMinersKeyPairs[0], recoverProposal);
    await ApproveAsync(InitialMinersKeyPairs[1], recoverProposal);
    await ApproveAsync(InitialMinersKeyPairs[2], recoverProposal);
    await ApproveAsync(InitialMinersKeyPairs[3], recoverProposal);
    // Miner 4 is "offline" - doesn't vote
    
    // Step 9: Verify proposal cannot be released (ToBeReleased = false)
    var proposalInfo = await ParliamentContractStub.GetProposal.CallAsync(recoverProposal);
    proposalInfo.ToBeReleased.ShouldBe(false);  // LOCKED OUT - need 5/5 but only have 4/5
    
    // Result: MethodFeeController is permanently locked to impossible organization
    // No way to change fees or controller ever again
}
```

## Notes

This vulnerability demonstrates a critical design flaw where the governance system can irreversibly lock itself out of fee management authority. The issue is particularly concerning because it could occur accidentally through well-intentioned governance actions, not just malicious attacks. The lack of any recovery mechanism means this represents a permanent loss of critical protocol functionality affecting all system contracts.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L24-33)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L91-109)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo();

        // Parliament Auth Contract maybe not deployed.
        if (State.ParliamentContract.Value != null)
        {
            defaultAuthority.OwnerAddress =
                State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
            defaultAuthority.ContractAddress = State.ParliamentContract.Value;
        }

        State.MethodFeeController.Value = defaultAuthority;
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

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L190-196)
```csharp
            createOrganizationInput.ProposalReleaseThreshold.MinimalVoteThreshold = 10000;
            createOrganizationInput.ProposalReleaseThreshold.MaximalAbstentionThreshold = 0;
            createOrganizationInput.ProposalReleaseThreshold.MaximalRejectionThreshold = 0;
            var transactionResult =
                await minerParliamentContractStub.CreateOrganization.SendAsync(createOrganizationInput);
            transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L83-88)
```csharp
    public override Empty UpdateCandidateInformation(UpdateCandidateInformationInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) ==
            Context.Sender || Context.Sender == GetEmergencyResponseOrganizationAddress(),
            "Only consensus contract can update candidate information.");
```
