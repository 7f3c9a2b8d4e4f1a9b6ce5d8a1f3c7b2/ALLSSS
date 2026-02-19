### Title
Method Fee Controller Frontrunning Vulnerability Allows Governance Censorship

### Summary
The `ChangeMethodFeeController()` function in the MultiToken contract contains a timing attack vulnerability where the current controller can prevent legitimate governance transitions by frontrunning approved proposals. By creating and releasing a competing proposal before a legitimate governance proposal executes, malicious controllers can maintain control indefinitely and censor governance decisions.

### Finding Description

The vulnerability exists in the `ChangeMethodFeeController()` function which validates that the caller is the current controller: [1](#0-0) 

The authorization check at line 27 validates `Context.Sender` against the CURRENT value of `State.MethodFeeController.Value.OwnerAddress`. This creates a Time-of-Check-Time-of-Use (TOCTOU) vulnerability.

**Root Cause:** The authorization check uses the current state rather than the state when the proposal was created, combined with no mutual exclusion between competing proposals targeting the same state variable.

**Execution Path:**

When a governance proposal is executed through Parliament's Release method, it uses a virtual inline transaction where `Context.Sender` becomes the organization address: [2](#0-1) 

The virtual address is calculated from the organization hash: [3](#0-2) 

**Why Protections Fail:**

1. Multiple proposals can simultaneously target `ChangeMethodFeeController()` with different parameters
2. No proposal ordering or state locking mechanism exists
3. Only the PROPOSER can release their proposal, creating a race condition between proposers
4. The first proposal to execute succeeds; all subsequent proposals fail authorization

The same vulnerability pattern exists in all ACS1-implementing contracts: [4](#0-3) 

### Impact Explanation

**High Severity - Governance Censorship Attack**

**Concrete Harm:**
- Legitimate governance transitions of method fee controller authority can be permanently blocked
- Current malicious controllers can maintain control indefinitely by repeatedly frontrunning legitimate proposals
- Breaks the fundamental governance transition mechanism across all ACS1-implementing contracts (MultiToken, Parliament, Association, Referendum, Configuration, Consensus, CrossChain, Election, Treasury, Profit, TokenConverter, TokenHolder, Vote, NFT, Economic contracts)

**Who Is Affected:**
- All users and governance participants attempting to change method fee controllers
- The entire protocol's governance integrity for method fee configuration

**Protocol Damage:**
- Complete breakdown of governance authority transfer mechanism
- Enables censorship-resistant control by malicious actors
- Undermines decentralized governance design

### Likelihood Explanation

**High Likelihood - Readily Exploitable**

**Attacker Capabilities Required:**
1. Ability to propose to the current controller organization (typically requires being in proposer whitelist or being a parliament member)
2. Sufficient voting power to approve the competing proposal (if attackers control current governance)
3. Ability to monitor pending proposals and release timing

**Attack Complexity:** Low
- Create competing proposal P2: `ChangeMethodFeeController({OwnerAddress: AttackerOrg, ...})`
- Get P2 approved by controlled voters
- Release P2 before legitimate proposal P1
- P1 becomes permanently unexecutable

**Feasibility Conditions:**
- Attackers already control the current method fee controller organization
- Can coordinate to approve and release proposals quickly
- Only requires standard proposal creation/approval/release operations

**Detection/Prevention:** None
- No on-chain mechanism prevents multiple proposals targeting the same state
- No way for legitimate proposers to guarantee their proposal executes first
- Race condition is inherent to the design

**Economic Rationality:**
- Low cost: Only proposal creation and transaction gas fees
- High benefit: Maintain permanent control over method fee governance

### Recommendation

**Immediate Mitigation:**

1. **Implement Proposal Commit-Reveal or Time-Lock:**
   Add a mandatory delay between proposal approval and release to prevent frontrunning:
   ```
   Add field: TimestampSeconds approval_time to ProposalInfo
   In Release(): Assert(Context.CurrentBlockTime >= proposal.approval_time + MIN_DELAY)
   ```

2. **Add State Version Check:**
   Store the expected controller state in the proposal and validate it hasn't changed:
   ```
   In ChangeMethodFeeController():
   - Add parameter: Hash expectedControllerHash
   - Assert(HashHelper.ComputeFrom(State.MethodFeeController.Value) == expectedControllerHash, 
           "Controller state changed since proposal creation")
   ```

3. **Implement Proposal Priority or Nonce System:**
   Add monotonically increasing nonce to controller changes:
   ```
   State.MethodFeeControllerNonce
   In ChangeMethodFeeController():
   - Add parameter: int64 expectedNonce
   - Assert(State.MethodFeeControllerNonce == expectedNonce, "Controller changed by competing proposal")
   - State.MethodFeeControllerNonce++
   ```

**Invariant to Add:**
- Only one controller change proposal can be active at a time, OR
- Controller changes must reference and validate the expected current state

**Test Cases to Prevent Regression:**
1. Create two approved proposals to change the same controller
2. Release second proposal first
3. Verify first proposal fails with clear error message
4. Verify mechanism prevents frontrunning (time-lock, state version, or nonce)

### Proof of Concept

**Initial State:**
- Organization A controls method fee: `State.MethodFeeController.Value = {OwnerAddress: A, ContractAddress: Parliament}`
- User X has proposal authority in Org A

**Attack Sequence:**

1. **Legitimate Governance (Time T0):**
   - User X creates Proposal P1 in Organization A
   - P1 parameters: `ChangeMethodFeeController({OwnerAddress: B, ContractAddress: Parliament})`
   - P1 approved by parliament members at T1
   - P1 ready to release

2. **Attack (Time T2, T2 < T3):**
   - Attacker Y (also has proposal authority in Org A) observes P1
   - Attacker Y creates Proposal P2 in Organization A
   - P2 parameters: `ChangeMethodFeeController({OwnerAddress: C, ContractAddress: Parliament})`
   - Where C is an attacker-controlled organization
   - P2 approved by colluding members at T2
   - **Attacker Y releases P2 at T2** (before User X releases P1)

3. **P2 Execution (Time T2):**
   - Parliament.Release() called by Attacker Y for P2
   - Virtual inline call: `Context.Sender = A` (Organization A's virtual address)
   - ChangeMethodFeeController() line 27 check: `A == A` ✓ PASSES
   - Line 31 executes: `State.MethodFeeController.Value = {OwnerAddress: C, ...}`
   - **Controller now changed to C**

4. **P1 Execution Attempt (Time T3):**
   - User X releases P1 at T3
   - Parliament.Release() called for P1
   - Virtual inline call: `Context.Sender = A` (Organization A's virtual address)
   - ChangeMethodFeeController() line 27 check: `A == C` ✗ **FAILS**
   - Transaction reverts: "Unauthorized behavior."
   - **Legitimate governance proposal permanently blocked**

**Expected vs Actual Result:**
- **Expected:** P1 should successfully transfer control to Organization B (legitimate governance decision)
- **Actual:** P1 fails authorization check, Attacker maintains control via Organization C

**Success Condition:** 
Attacker successfully prevents governance transition by frontrunning with competing proposal, maintaining control indefinitely through repeated application of this attack.

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L293-312)
```csharp
    private OrganizationHashAddressPair CalculateOrganizationHashAddressPair(
        CreateOrganizationInput createOrganizationInput)
    {
        var organizationHash = HashHelper.ComputeFrom(createOrganizationInput);
        var organizationAddress =
            Context.ConvertVirtualAddressToContractAddressWithContractHashName(
                CalculateVirtualHash(organizationHash, createOrganizationInput.CreationToken));
        return new OrganizationHashAddressPair
        {
            OrganizationAddress = organizationAddress,
            OrganizationHash = organizationHash
        };
    }

    private Hash CalculateVirtualHash(Hash organizationHash, Hash creationToken)
    {
        return creationToken == null
            ? organizationHash
            : HashHelper.ConcatAndCompute(organizationHash, creationToken);
    }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L21-30)
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
