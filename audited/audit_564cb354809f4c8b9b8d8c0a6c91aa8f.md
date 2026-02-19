### Title
Parliament Can Forcibly Seize Control of Any Candidate Through Unchecked Admin Override

### Summary
The `SetCandidateAdmin()` function contains a critical access control bypass where the Parliament default organization address can forcibly change any candidate's admin without permission checks. Once control is seized, Parliament can quit the candidate's election participation, replace their public key, and redirect their mining/subsidy rewards to any address, fundamentally undermining candidate autonomy and decentralization.

### Finding Description

The vulnerability exists in the permission check logic of `SetCandidateAdmin()`: [1](#0-0) 

When `Context.Sender` equals the Parliament default address, the entire permission validation block (lines 29-40) is bypassed. The function proceeds directly to setting the new admin without verifying:
- The current admin's consent (line 38)
- The original candidate owner's approval (line 32-33)

The Parliament default address is obtained through: [2](#0-1) 

Once Parliament controls a candidate's admin, they gain three critical powers:

**1. Force Candidate to Quit Election:** [3](#0-2) 

**2. Replace Candidate's Public Key:** [4](#0-3) 

**3. Redirect Candidate's Profit Rewards:** [5](#0-4) 

### Impact Explanation

**Direct Financial Impact:**
- Parliament can redirect any candidate's mining rewards and subsidy profits by first seizing admin control, then calling `SetProfitsReceiver` in the Treasury contract to change the beneficiary address
- Candidates lose their earned rewards without consent

**Governance Centralization:**
- Parliament can force candidates to quit election at will, centralizing control over who can participate in consensus
- Undermines the decentralized election system by allowing governance to override candidate autonomy
- Enables censorship of candidates through forced admin changes

**Operational Disruption:**
- Parliament can replace candidate public keys, disrupting their mining operations
- Candidates who invested tokens to announce election (locked via `LockCandidateNativeToken`) can have their participation terminated unilaterally

**Severity Justification:**
This is HIGH severity because it violates the fundamental principle of candidate autonomy in a decentralized consensus system. While Parliament requires 2/3 miner approval for proposals, this mechanism grants excessive power that can be used for censorship, reward theft, or coercion of candidates.

### Likelihood Explanation

**Attack Prerequisites:**
1. Parliament must create a proposal calling `SetCandidateAdmin` with target candidate and new admin address
2. Proposal must achieve 2/3 miner approval and be released
3. Proposal execution calls `SetCandidateAdmin` with Parliament as sender

**Execution Complexity:**
- **Low complexity**: Single transaction execution after proposal approval
- **Standard governance flow**: Uses existing Parliament proposal mechanism
- **No technical exploits needed**: Vulnerability is by design in the permission check

**Feasibility Conditions:**
- Parliament consensus required (2/3 miners), but this is the normal governance process
- No additional barriers once proposal passes
- Can target any candidate, including active miners

**Economic Rationality:**
- Governance could use this for:
  - Censoring dissenting candidates
  - Redirecting rewards to preferred addresses  
  - Coercing candidates into compliance
- Attack cost is only the political capital to pass a Parliament proposal

**Detection/Operational Constraints:**
- Proposal would be public and visible on-chain
- However, once passed and executed, admin change is immediate and irreversible
- Victim candidates have no mechanism to prevent or revert the change

**Probability Assessment:**
While requiring Parliament consensus provides some safeguard, the capability fundamentally exists and could be exercised under various scenarios (emergency response, hostile governance takeover, or rationalized as "legitimate governance"). The lack of any consent mechanism from affected candidates makes this exploitable whenever Parliament decides to act.

### Recommendation

**1. Remove Parliament Override Entirely:**
Eliminate the special case for Parliament default address:

```csharp
public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
{
    Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

    var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
    
    // Remove the Parliament bypass - always require permission
    if (State.CandidateAdmins[pubkey] == null)
    {
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

**2. Alternative: Require Candidate Consent:**
If Parliament override is truly necessary for emergency scenarios, implement a two-step process:
- Parliament proposes admin change
- Candidate (or current admin) must approve within timeframe
- Only execute change after both parties consent

**3. Add Invariant Checks:**
- Log all admin changes with events including old admin, new admin, and initiator
- Implement admin change cooldown period
- Add candidate-initiated admin recovery mechanism

**4. Test Cases:**
- Test that Parliament cannot change admin without consent
- Test that only current admin can transfer admin rights
- Test emergency scenarios have proper safeguards and transparency

### Proof of Concept

**Initial State:**
- Candidate Alice announces election with admin address = Alice's org address
- Alice's admin is set: `State.CandidateAdmins[AlicePubkey] = AliceOrgAddress`
- Alice participates in mining and receives rewards to AliceOrgAddress

**Attack Sequence:**

**Step 1:** Parliament creates proposal
```
CreateProposal({
  OrganizationAddress: ParliamentDefaultOrg,
  ToAddress: ElectionContract,
  MethodName: "SetCandidateAdmin",
  Params: {
    Pubkey: AlicePubkey,
    Admin: MaliciousAddress  // Controlled by attacker
  }
})
```

**Step 2:** Proposal achieves 2/3 miner approval and is released

**Step 3:** Proposal executes `SetCandidateAdmin`
- Context.Sender = ParliamentDefaultOrg
- Line 27 condition: `Context.Sender == GetParliamentDefaultAddress()` = TRUE
- Lines 29-40 permission checks are SKIPPED
- Line 42: `State.CandidateAdmins[AlicePubkey] = MaliciousAddress`

**Step 4:** Attacker exploits seized control
```
// Force quit election
QuitElection({Value: AlicePubkey})  // Called by MaliciousAddress

// OR redirect rewards
SetProfitsReceiver({  // In Treasury contract
  Pubkey: AlicePubkey,
  ProfitsReceiverAddress: AttackerAddress
})  // Called by MaliciousAddress (verified as admin)

// OR replace public key
ReplaceCandidatePubkey({
  OldPubkey: AlicePubkey,
  NewPubkey: AttackerControlledPubkey
})  // Called by MaliciousAddress
```

**Expected Result:** 
Permission denied - Alice's admin cannot be changed without AliceOrgAddress consent

**Actual Result:**
Admin successfully changed to MaliciousAddress, enabling full control over Alice's candidate operations and reward redirection

**Success Condition:**
`State.CandidateAdmins[AlicePubkey] == MaliciousAddress` after Step 3, with Alice having no ability to prevent or reverse this change

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L608-609)
```csharp
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
```
