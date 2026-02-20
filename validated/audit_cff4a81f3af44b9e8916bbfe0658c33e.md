# Audit Report

## Title
Parliament Can Forcibly Seize Control of Any Candidate Through Unchecked Admin Override

## Summary
The `SetCandidateAdmin()` function in the Election contract grants Parliament default organization unrestricted ability to forcibly change any candidate's admin without consent. This excessive privilege enables Parliament to force candidates to quit elections, replace their public keys, and redirect their mining/subsidy rewards, fundamentally undermining candidate autonomy in the decentralized consensus system.

## Finding Description

The vulnerability exists in the permission validation logic of `SetCandidateAdmin()`. When `Context.Sender` equals the Parliament default organization address, all permission checks are bypassed. [1](#0-0) 

The condition explicitly checks if the sender is NOT Parliament. When Parliament IS the sender, the entire permission validation block (lines 29-40) is skipped, allowing direct admin modification without verifying consent from the current admin or candidate owner. [2](#0-1) 

Parliament's default organization address is obtained via: [3](#0-2) 

When Parliament releases an approved proposal, the transaction executes with the organization's virtual address as `Context.Sender`: [4](#0-3) 

The organization address calculation ensures the sender matches the stored default organization: [5](#0-4) 

Once Parliament seizes candidate admin control, three critical powers become available:

**1. Force Candidate to Quit Election:** [6](#0-5) 

**2. Replace Candidate's Public Key:** [7](#0-6) 

**3. Redirect Candidate's Profit Rewards:** [8](#0-7) 

## Impact Explanation

This represents **HIGH severity** governance centralization risk with multiple impact vectors:

**Direct Financial Impact:**
- Parliament can redirect any candidate's mining rewards and subsidy profits by first seizing admin control via `SetCandidateAdmin`, then calling `SetProfitsReceiver` in Treasury to change the beneficiary address
- Candidates lose their earned rewards without any consent mechanism or recourse

**Governance Centralization:**
- Parliament can force candidates to quit election at will, centralizing control over who participates in consensus
- Undermines the decentralized election system by allowing governance to override candidate autonomy
- Enables censorship of dissenting candidates through forced admin changes and election termination

**Operational Disruption:**
- Parliament can replace candidate public keys, disrupting their mining operations and block production capabilities
- Candidates who locked 100,000 ELF to announce election can have their participation terminated unilaterally

While Parliament requires 2/3 miner approval for proposals, this mechanism grants excessive unilateral power over individual candidates without their consent, time delays, or appeals process - violating fundamental decentralization principles.

## Likelihood Explanation

The attack path is **feasible and straightforward** through standard governance flow:

**Execution Steps:**
1. Parliament member creates proposal calling `SetCandidateAdmin` with target candidate pubkey and Parliament-controlled admin address
2. Proposal achieves 2/3 miner approval threshold through Parliament voting mechanism
3. Proposer releases the approved proposal, which executes with Parliament organization address as sender
4. Admin change occurs immediately and irreversibly

**Feasibility Factors:**
- **Low technical complexity:** Single transaction execution after proposal approval
- **Standard governance mechanism:** Uses existing Parliament proposal system
- **No additional barriers:** Once proposal passes, admin seizure is immediate with no consent from affected candidate
- **Can target any candidate:** Including active miners and candidates with substantial vote weight

The requirement for 2/3 miner approval provides some democratic safeguard, but the fundamental capability exists and could be exercised under scenarios such as emergency response, protocol changes rationalized as "legitimate governance," or coercion of candidates into compliance. The absence of any consent mechanism from affected candidates makes this exploitable whenever Parliament decides to act.

## Recommendation

Implement one or more of the following protections:

1. **Remove Parliament bypass entirely:** Require Parliament to go through the same consent mechanisms as other admin changes
2. **Add candidate consent requirement:** Implement a two-step process where candidate must explicitly approve admin changes even when initiated by Parliament
3. **Implement time delay:** Add a mandatory timelock period (e.g., 7 days) between admin change proposal and execution, allowing candidates to respond
4. **Add appeals mechanism:** Create an emergency escape mechanism where candidates can appeal to a different governance body or lock their admin settings

Example fix for option 1:

```csharp
public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
{
    Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

    // Permission check - removed Parliament bypass
    var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
    if (State.CandidateAdmins[pubkey] == null)
    {
        // If admin is not set before
        Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
            "No permission.");
    }
    else
    {
        var oldCandidateAdmin = State.CandidateAdmins[pubkey];
        Assert(Context.Sender == oldCandidateAdmin, "No permission.");
    }

    State.CandidateAdmins[pubkey] = input.Admin;
    // ... rest of function
}
```

## Proof of Concept

```csharp
// Test demonstrating Parliament's ability to forcibly change candidate admin
[Fact]
public async Task Parliament_CanForciblySSeizeCandidateAdmin_Test()
{
    // Setup: Candidate announces election with their own admin
    var candidateKeyPair = ValidationDataCenterKeyPairs[0];
    var candidateAdmin = ValidationDataCenterKeyPairs[1];
    var candidateAdminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
    
    await AnnounceElectionAsync(candidateKeyPair, candidateAdminAddress);
    
    // Verify initial admin
    var initialAdmin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = candidateKeyPair.PublicKey.ToHex() });
    initialAdmin.ShouldBe(candidateAdminAddress);
    
    // Parliament creates proposal to seize admin control
    var parliamentAddress = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var newAdmin = Address.FromPublicKey(ValidationDataCenterKeyPairs[2].PublicKey); // Parliament-controlled
    
    var proposalId = await CreateParliamentProposalAsync(
        ElectionContractAddress,
        nameof(ElectionContractStub.SetCandidateAdmin),
        new SetCandidateAdminInput
        {
            Pubkey = candidateKeyPair.PublicKey.ToHex(),
            Admin = newAdmin
        });
    
    // Get 2/3 miner approval
    await ApproveWithMinersAsync(proposalId);
    
    // Release proposal - executes with Parliament org address as sender
    await ReleaseProposalAsync(proposalId);
    
    // Verify Parliament successfully seized admin WITHOUT candidate consent
    var newAdminResult = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = candidateKeyPair.PublicKey.ToHex() });
    newAdminResult.ShouldBe(newAdmin);
    newAdminResult.ShouldNotBe(candidateAdminAddress); // Original admin replaced
    
    // Demonstrate Parliament can now force quit election
    var newAdminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, ValidationDataCenterKeyPairs[2]);
    await newAdminStub.QuitElection.SendAsync(new StringValue 
    { 
        Value = candidateKeyPair.PublicKey.ToHex() 
    });
    
    // Verify candidate forcibly removed from election
    var candidates = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidates.Value.ShouldNotContain(ByteString.CopyFrom(candidateKeyPair.PublicKey));
}
```

## Notes

This vulnerability represents an **intentional design choice** that grants Parliament excessive privilege scope. While the 2/3 approval requirement provides some democratic safeguard, the absence of candidate consent, time delays, or appeals mechanisms creates a centralized control point that contradicts decentralized governance principles. The vulnerability is particularly concerning because it enables Parliament to financially penalize dissenting candidates through reward redirection or force their removal from consensus participation entirely.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L27-40)
```csharp
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
            }
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L42-42)
```csharp
        State.CandidateAdmins[pubkey] = input.Admin;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L66-73)
```csharp
    private Address GetParliamentDefaultAddress()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        return State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L236-236)
```csharp
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L138-140)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L296-299)
```csharp
        var organizationHash = HashHelper.ComputeFrom(createOrganizationInput);
        var organizationAddress =
            Context.ConvertVirtualAddressToContractAddressWithContractHashName(
                CalculateVirtualHash(organizationHash, createOrganizationInput.CreationToken));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```
