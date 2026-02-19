### Title
Pending Proposals from Removed Proposers Can Still Be Executed After Whitelist Changes

### Summary
The `ChangeOrganizationProposerWhiteList()` function can remove proposers from the whitelist while their proposals are still pending, but the `Release()` function does not re-validate proposer authorization. This allows removed proposers to execute previously created proposals even after being removed from the whitelist, undermining governance security controls. This vulnerability affects Parliament, Association, and Referendum contracts.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The authorization check for proposers occurs only at proposal creation time, not at release time. When a proposal is created, `AssertIsAuthorizedProposer` validates the proposer is in the whitelist or is a parliament member: [2](#0-1) [3](#0-2) 

However, when a proposal is released, only the original proposer identity is checked, without re-validating their current authorization status: [4](#0-3) 

The `ChangeOrganizationProposerWhiteList` function updates the whitelist without any checks for pending proposals from addresses being removed. The whitelist check helper used at creation time: [5](#0-4) 

**Why Protections Fail:**
The proposer's address is stored in the `ProposalInfo` at creation time and never re-verified. The `Release` function at line 135 only verifies `Context.Sender.Equals(proposalInfo.Proposer)`, confirming the caller is the same address that created the proposal, but does not call `AssertIsAuthorizedProposer` or `ValidateAddressInWhiteList` to check if that address is still authorized.

**Same Vulnerability in Other Governance Contracts:**

Association: [6](#0-5) 

Referendum: [7](#0-6) 

### Impact Explanation

**Governance Security Bypass:**
When a proposer is removed from the whitelist (typically due to discovered malicious behavior, compromised keys, or loss of trust), the intent is to revoke their proposal creation authority. However, any proposals they created while authorized remain valid and executable indefinitely until expiration.

**Concrete Harm:**
- A malicious or compromised proposer can create proposals before detection
- After discovery, governance removes them from the whitelist via `ChangeOrganizationProposerWhiteList`
- The removed proposer's pending proposals can still collect votes and be released
- This allows execution of proposals from untrusted addresses, defeating the whitelist security model

**Who Is Affected:**
- All organizations using Parliament contract (including the default organization managing system governance)
- All organizations using Association contract (multi-sig governance)
- All organizations using Referendum contract (token-weighted voting)

**Severity Justification:**
High severity because this directly undermines governance authorization controls. The whitelist mechanism is a critical security boundary, and its compromise can lead to unauthorized system configuration changes, fund movements, or contract upgrades depending on the proposal content.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must initially be a legitimate authorized proposer (in whitelist or parliament member)
- No special permissions required beyond normal proposal creation and release rights
- Can be an insider threat or compromised authorized address

**Attack Complexity:**
Low complexity - straightforward attack sequence:
1. Create proposal while authorized
2. Wait to be removed from whitelist (or trigger removal through malicious behavior)
3. Let the proposal collect votes naturally
4. Call `Release()` once threshold is reached

**Feasibility Conditions:**
- Highly feasible - requires no special blockchain state manipulation
- Proposals have expiration times but these can be set far in the future at creation (tested in Parliament contract with multi-day expirations)
- The test suite confirms removed proposers cannot create NEW proposals but does not test release of OLD proposals: [8](#0-7) 

**Economic Rationality:**
Very rational - maintaining a pending proposal has zero cost to the attacker. They simply wait for votes and then execute at no additional expense.

**Detection Constraints:**
Difficult to detect proactively since the proposal appears legitimate in the system. Governance would need to manually track and clear proposals from removed proposers.

### Recommendation

**Code-Level Mitigation:**

Add proposer authorization re-validation in the `Release` function. Modify Parliament.cs (and similarly for Association/Referendum):

```csharp
public override Empty Release(Hash proposalId)
{
    var proposalInfo = GetValidProposal(proposalId);
    Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
    
    // ADD THIS CHECK: Re-validate proposer is still authorized
    AssertIsAuthorizedProposer(proposalInfo.OrganizationAddress, proposalInfo.Proposer);
    
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), 
        proposalInfo.ToAddress,
        proposalInfo.ContractMethodName, 
        proposalInfo.Params);
    Context.Fire(new ProposalReleased { ProposalId = proposalId });
    State.Proposals.Remove(proposalId);
    return new Empty();
}
```

**Alternative Mitigation:**

Optionally, add a check in `ChangeOrganizationProposerWhiteList` to automatically clear pending proposals from removed proposers, though this may be less desirable as it requires iterating proposals.

**Invariant to Enforce:**
"A proposal can only be released if its proposer is currently authorized according to the organization's current whitelist and authorization rules."

**Test Cases to Add:**
1. Create proposal while proposer is in whitelist
2. Remove proposer from whitelist via `ChangeOrganizationProposerWhiteList`
3. Attempt to release the proposal - should fail with "Unauthorized to propose"
4. Verify the same behavior for Association and Referendum contracts

### Proof of Concept

**Initial State:**
- Address A is in the proposer whitelist for an organization
- Organization has standard approval thresholds (e.g., majority of parliament members)

**Exploit Sequence:**

1. **Address A creates a malicious proposal** (e.g., transferring treasury funds):
   - Call `CreateProposal()` with malicious parameters
   - Proposal ID is generated and stored
   - Authorization passes because A is in whitelist

2. **Governance discovers A is malicious and removes them:**
   - Create and approve a proposal calling `ChangeOrganizationProposerWhiteList()`
   - New whitelist excludes Address A
   - Whitelist is updated

3. **Verify A cannot create new proposals:**
   - Address A calls `CreateProposal()`
   - Transaction fails with "Unauthorized to propose" ✓ Expected

4. **Address A's old proposal still gets approved:**
   - Parliament members vote on the old proposal (unaware proposer was removed)
   - Approval threshold is reached

5. **Address A calls `Release()` on their old proposal:**
   - Transaction succeeds ✗ Unexpected
   - Malicious proposal executes
   - System state is modified by unauthorized proposer

**Expected Result:** 
Release should fail with "Unauthorized to propose" error after proposer removed from whitelist

**Actual Result:**
Release succeeds because authorization is only checked at creation time, not release time

**Success Condition for Exploit:**
Proposal from removed proposer executes successfully, demonstrating governance bypass

### Notes

This vulnerability represents a gap between the security model's intent and implementation. The whitelist mechanism is designed to control who can propose governance actions, but the implementation only enforces this at proposal creation, not execution. This is particularly concerning for long-lived proposals where circumstances may change significantly between creation and execution. The same vulnerability pattern exists across all three governance contracts (Parliament, Association, Referendum), indicating a systematic design issue in the ACS3 governance standard implementation.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L61-66)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L162-177)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var defaultOrganizationAddress = State.DefaultOrganizationAddress.Value;
        Assert(defaultOrganizationAddress == Context.Sender, "No permission.");
        var organization = State.Organizations[defaultOrganizationAddress];
        Assert(
            input.Proposers.Count > 0 || !organization.ProposerAuthorityRequired ||
            organization.ParliamentMemberProposingAllowed, "White list can't be empty.");
        State.ProposerWhiteList.Value = input;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L22-34)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        // It is a valid proposer if
        // authority check is disable,
        // or sender is in proposer white list,
        // or sender is one of miners when member proposing allowed.
        Assert(
            !organization.ProposerAuthorityRequired || ValidateAddressInWhiteList(proposer) ||
            (organization.ParliamentMemberProposingAllowed && ValidateParliamentMemberAuthority(proposer)),
            "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L201-204)
```csharp
    private bool ValidateAddressInWhiteList(Address address)
    {
        return State.ProposerWhiteList.Value.Proposers.Any(p => p == address);
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-200)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);

        Context.Fire(new ProposalReleased
        {
            ProposalId = input,
            OrganizationAddress = proposalInfo.OrganizationAddress
        });
        State.Proposals.Remove(input);

        return new Empty();
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L163-177)
```csharp
    public override Empty Release(Hash input)
    {
        var proposal = GetValidProposal(input);
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
        var organization = State.Organizations[proposal.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposal.ToAddress,
            proposal.ContractMethodName, proposal.Params);

        Context.Fire(new ProposalReleased { ProposalId = input });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L790-839)
```csharp
    public async Task Change_OrganizationProposalWhitelist_Test()
    {
        var minimalApproveThreshold = 1;
        var minimalVoteThreshold = 1;
        var maximalAbstentionThreshold = 1;
        var maximalRejectionThreshold = 1;
        var organizationAddress = await CreateOrganizationAsync(minimalApproveThreshold, minimalVoteThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, Reviewer1);

        var proposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer2 }
        };

        var associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
        var changeProposalId = await CreateAssociationProposalAsync(Reviewer1KeyPair, proposerWhiteList,
            nameof(associationContractStub.ChangeOrganizationProposerWhiteList), organizationAddress);
        await ApproveAsync(Reviewer1KeyPair, changeProposalId);
        var releaseResult = await associationContractStub.Release.SendAsync(changeProposalId);
        releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        await TransferToOrganizationAddressAsync(organizationAddress);
        var transferInput = new TransferInput
        {
            Symbol = "ELF",
            Amount = 100,
            To = Reviewer1,
            Memo = "Transfer"
        };
        associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
        var createProposalInput = new CreateProposalInput
        {
            ContractMethodName = nameof(TokenContractStub.Approve),
            ToAddress = TokenContractAddress,
            Params = transferInput.ToByteString(),
            ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(2),
            OrganizationAddress = organizationAddress
        };
        var result = await associationContractStub.CreateProposal.SendWithExceptionAsync(createProposalInput);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        result.TransactionResult.Error.ShouldContain("Unauthorized to propose.");

        //Verify association proposal
        var verifyResult = await associationContractStub.ValidateProposerInWhiteList.CallAsync(
            new ValidateProposerInWhiteListInput
            {
                OrganizationAddress = organizationAddress,
                Proposer = Reviewer2
            });
        verifyResult.Value.ShouldBeTrue();
    }
```
