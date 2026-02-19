# Audit Report

## Title
Parliament Can Forcibly Seize Control of Any Candidate Through Unchecked Admin Override

## Summary
The `SetCandidateAdmin()` function in the Election contract contains an intentional but excessive privilege escalation where the Parliament default organization address can forcibly change any candidate's admin without obtaining consent from the candidate or current admin. This enables Parliament to force candidates to quit elections, replace their public keys, and redirect their mining/subsidy rewards, fundamentally undermining candidate autonomy in the decentralized consensus system.

## Finding Description

The vulnerability exists in the permission check logic of `SetCandidateAdmin()`. When `Context.Sender` equals the Parliament default address, the entire permission validation block is bypassed: [1](#0-0) 

The condition at line 27 explicitly checks if the sender is NOT the Parliament default address. If the sender IS Parliament, lines 29-40 containing all permission checks are skipped, and the function proceeds directly to line 42 to set the new admin without verifying consent from the current admin or the candidate owner.

The Parliament default address is obtained through: [2](#0-1) 

When Parliament releases an approved proposal, the transaction executes with the organization address as `Context.Sender`: [3](#0-2) 

Once Parliament controls a candidate's admin, they gain three critical powers:

**1. Force Candidate to Quit Election:** [4](#0-3) 

**2. Replace Candidate's Public Key:** [5](#0-4) 

**3. Redirect Candidate's Profit Rewards:** [6](#0-5) 

## Impact Explanation

This represents a **HIGH severity** governance centralization risk with multiple impact vectors:

**Direct Financial Impact:**
- Parliament can redirect any candidate's mining rewards and subsidy profits by first seizing admin control via `SetCandidateAdmin`, then calling `SetProfitsReceiver` in the Treasury contract to change the beneficiary address
- Candidates lose their earned rewards without any consent mechanism

**Governance Centralization:**
- Parliament can force candidates to quit election at will, centralizing control over who can participate in consensus
- Undermines the decentralized election system by allowing governance to override candidate autonomy
- Enables censorship of dissenting candidates through forced admin changes and election termination

**Operational Disruption:**
- Parliament can replace candidate public keys, disrupting their mining operations and block production capabilities
- Candidates who invested tokens to announce election (100,000 ELF locked via `LockCandidateNativeToken`) can have their participation terminated unilaterally

While Parliament requires 2/3 miner approval for proposals, this mechanism grants excessive unilateral power that violates fundamental decentralization principles. There is no consent mechanism, appeals process, or time delay for affected candidates.

## Likelihood Explanation

The attack path is **feasible and straightforward**:

**Attack Prerequisites:**
1. Parliament creates a proposal calling `SetCandidateAdmin` with target candidate pubkey and new admin address (Parliament-controlled)
2. Proposal achieves 2/3 miner approval threshold
3. Proposer releases the approved proposal

**Execution Complexity:**
- **Low technical complexity**: Single transaction execution after proposal approval
- **Standard governance flow**: Uses existing Parliament proposal mechanism without exploits
- **No additional barriers**: Once proposal passes, admin change is immediate and irreversible

**Feasibility Conditions:**
- Requires Parliament consensus (2/3 miners), which is the normal governance process
- Can target any candidate including active miners
- No emergency-only restrictions or additional safeguards

**Probability Assessment:**
While requiring 2/3 miner approval provides some democratic safeguard, the capability fundamentally exists and could be exercised under various scenarios:
- Emergency response to perceived threats
- Hostile governance takeover with majority control
- Rationalized as "legitimate governance" for protocol changes
- Coercion of candidates into compliance with governance decisions

The lack of any consent mechanism from affected candidates makes this exploitable whenever Parliament decides to act, limited only by the political cost of obtaining 2/3 approval.

## Recommendation

Implement a multi-stage consent mechanism that preserves candidate autonomy while allowing legitimate emergency governance:

1. **Remove the unconditional Parliament bypass** - Require candidate consent even for Parliament:
```csharp
// Remove the Parliament bypass at line 27
// Always require consent from current admin or candidate owner

var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;

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
```

2. **Add a time-locked emergency override** - If Parliament override is deemed necessary for extreme cases:
```csharp
// Proposal-based admin change with time delay
public override Empty ProposeAdminChange(ProposeAdminChangeInput input)
{
    Assert(Context.Sender == GetParliamentDefaultAddress(), "Only Parliament can propose admin changes.");
    
    State.ProposedAdminChanges[input.Pubkey] = new ProposedAdminChange
    {
        NewAdmin = input.Admin,
        ProposalTime = Context.CurrentBlockTime,
        EffectiveTime = Context.CurrentBlockTime.AddDays(7) // 7-day time lock
    };
    
    return new Empty();
}

public override Empty ExecuteAdminChange(StringValue pubkey)
{
    var proposal = State.ProposedAdminChanges[pubkey.Value];
    Assert(proposal != null, "No proposed admin change.");
    Assert(Context.CurrentBlockTime >= proposal.EffectiveTime, "Time lock not expired.");
    
    State.CandidateAdmins[pubkey.Value] = proposal.NewAdmin;
    State.ProposedAdminChanges.Remove(pubkey.Value);
    
    return new Empty();
}
```

3. **Allow candidates to object** - Add a veto mechanism during the time lock period where the candidate can cancel the proposed change or migrate their stake.

## Proof of Concept

The following test demonstrates Parliament's ability to seize candidate admin control and force election quit:

```csharp
[Fact]
public async Task Parliament_Can_Seize_Candidate_Admin_Test()
{
    // Setup: Candidate announces election with their own admin
    var candidateKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = Address.FromPublicKey(candidateKeyPair.PublicKey);
    await AnnounceElectionAsync(candidateKeyPair, candidateAdmin);
    
    // Verify candidate is in election
    var candidatesBefore = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidatesBefore.Value.ShouldContain(ByteString.CopyFrom(candidateKeyPair.PublicKey));
    
    // Parliament creates proposal to seize admin
    var parliamentAddress = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var maliciousAdmin = SampleAddress.AddressList[0]; // Parliament-controlled address
    
    var proposalId = await CreateProposalAsync(
        parliamentAddress,
        nameof(ElectionContractStub.SetCandidateAdmin),
        new SetCandidateAdminInput
        {
            Pubkey = candidateKeyPair.PublicKey.ToHex(),
            Admin = maliciousAdmin
        });
    
    // Miners approve proposal (2/3 threshold)
    await ApproveWithMinersAsync(proposalId);
    
    // Release proposal - Parliament becomes sender
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Verify admin was seized without candidate consent
    var newAdmin = await ElectionContractStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = candidateKeyPair.PublicKey.ToHex() });
    newAdmin.ShouldBe(maliciousAdmin);
    
    // Now malicious admin can force candidate to quit
    var maliciousAdminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, 
        GetKeyPairForAddress(maliciousAdmin));
    
    await maliciousAdminStub.QuitElection.SendAsync(
        new StringValue { Value = candidateKeyPair.PublicKey.ToHex() });
    
    // Verify candidate was forcibly removed from election
    var candidatesAfter = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidatesAfter.Value.ShouldNotContain(ByteString.CopyFrom(candidateKeyPair.PublicKey));
}
```

This test proves that Parliament can execute `SetCandidateAdmin` without any permission checks, seize control of a candidate's admin, and then force the candidate to quit election - all without the candidate's consent.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```
