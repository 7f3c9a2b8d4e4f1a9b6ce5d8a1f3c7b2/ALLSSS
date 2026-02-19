### Title
Authorization Escalation via Immediate Controller Change Without Timelock in Genesis Contract Method Fee Provider

### Summary
The `ChangeMethodFeeController` function allows immediate and permanent controller changes without any timelock or delay mechanism. An attacker who gains temporary access to the current controller's OwnerAddress can escalate this temporary access into permanent control by changing the controller to their own organization address, with no ability to revert the change without going through the attacker's new controller.

### Finding Description
The vulnerability exists in the `ChangeMethodFeeController` function which only performs sender authorization and organization existence validation before immediately updating the controller state. [1](#0-0) 

The authorization check validates that the sender equals the current controller's OwnerAddress, but provides no protection against escalation attacks: [2](#0-1) 

When the current MethodFeeController.OwnerAddress is a governance organization (typically Parliament), an attacker who temporarily controls sufficient voting power can execute the following attack:

1. Create a governance proposal to call `ChangeMethodFeeController` with a new `AuthorityInfo` pointing to their controlled organization
2. Approve the proposal using their temporary voting majority
3. Release the proposal, which executes from the organization's virtual address [3](#0-2) 

The Parliament `Release` function executes proposals immediately via `Context.SendVirtualInlineBySystemContract` with no enforced delay between approval and execution. There is no minimum timelock period - proposals can be approved and released in rapid succession. [4](#0-3) 

The organization existence validation only confirms the new organization exists, not whether it represents a legitimate governance transition: [5](#0-4) 

Once the controller is changed, `State.MethodFeeController.Value` is immediately updated with no grace period or revocation mechanism. The same vulnerability pattern exists in related controller change functions: [6](#0-5) [7](#0-6) 

### Impact Explanation
**Severity: Critical** - An attacker who achieves temporary governance control can permanently hijack the Genesis contract's method fee controller, gaining indefinite control over:

- Method fee configuration for all Genesis contract functions via `SetMethodFee`
- The ability to set arbitrary fees that could economically DoS critical system operations
- Permanent authority over future controller changes

The Genesis contract (BasicContractZero) is the system's foundational contract responsible for all contract deployments and upgrades. Control over its method fees affects the entire blockchain's operational economics.

Once the controller is changed, legitimate governance loses all ability to revert the change without somehow regaining control of the attacker's organization, which may be impossible if the attacker controls a single-address organization or has configured an unbreakable threshold.

This violates the critical invariant: "Organization thresholds, proposer whitelist checks, proposal lifetime/expiration, correct organization hash resolution, method-fee provider authority."

### Likelihood Explanation
**Likelihood: Medium** - While the precondition requires temporary governance compromise, the attack is practical once that threshold is met:

**Attacker Capabilities Required:**
- Temporary control of >50% of Parliament miners (for default controller) OR majority control of the current controller organization
- Ability to create, approve, and release a governance proposal

**Attack Complexity:** Low - The attack uses standard governance mechanisms with no special exploits required. A single proposal can accomplish the entire attack.

**Feasible Scenarios:**
1. **Temporary Miner Compromise**: Attacker compromises multiple miner nodes through exploits or social engineering for a brief period
2. **Vote Manipulation**: Coordinated attack or vote buying in governance organization
3. **Time-window Exploitation**: Leveraging a temporary alignment of compromised or colluding validators

**Detection Constraints:** The attack appears as a legitimate governance proposal and may not be detected before execution. Once executed, the change is irreversible through normal channels.

**Economic Rationality:** If an attacker already has temporary governance control, escalating to permanent control has zero marginal cost and maximizes long-term value extraction.

### Recommendation
Implement a two-phase controller change mechanism with mandatory timelock delay:

1. **Add Timelock State Variables:**
```
SingletonState<AuthorityInfo> PendingMethodFeeController;
SingletonState<Timestamp> MethodFeeControllerChangeTime;
Int64State MethodFeeControllerTimelockPeriod; // e.g., 7 days
```

2. **Split into Two-Phase Process:**
   - `ProposeMethodFeeControllerChange(AuthorityInfo newController)` - Stage the change with timestamp
   - `FinalizeMethodFeeControllerChange()` - Execute after timelock period expires

3. **Add Cancellation Mechanism:**
   - `CancelMethodFeeControllerChange()` - Allow current controller to cancel pending changes

4. **Validation Checks:**
```csharp
public override Empty ProposeMethodFeeControllerChange(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
    Assert(CheckOrganizationExist(input), "Invalid authority input.");
    
    State.PendingMethodFeeController.Value = input;
    State.MethodFeeControllerChangeTime.Value = Context.CurrentBlockTime
        .AddSeconds(State.MethodFeeControllerTimelockPeriod.Value);
    
    return new Empty();
}

public override Empty FinalizeMethodFeeControllerChange(Empty input)
{
    Assert(State.PendingMethodFeeController.Value != null, "No pending change.");
    Assert(Context.CurrentBlockTime >= State.MethodFeeControllerChangeTime.Value, 
        "Timelock not expired.");
    
    State.MethodFeeController.Value = State.PendingMethodFeeController.Value;
    State.PendingMethodFeeController.Value = null;
    
    return new Empty();
}
```

5. **Apply Same Pattern** to `ChangeContractDeploymentController` and `ChangeCodeCheckController`

6. **Test Cases:**
   - Verify timelock enforcement prevents immediate finalization
   - Test cancellation by current controller during timelock period
   - Validate that expired pending changes cannot be finalized after new proposal
   - Confirm unauthorized addresses cannot finalize changes

### Proof of Concept

**Initial State:**
- Genesis contract deployed with Parliament as default MethodFeeController
- Parliament organization requires >50% miner approval
- Attacker temporarily controls 60% of miner nodes

**Attack Sequence:**

1. **T=0: Create Malicious Proposal**
   - Attacker creates Parliament proposal calling `ChangeMethodFeeController`
   - New `AuthorityInfo.OwnerAddress` = attacker-controlled organization
   - New `AuthorityInfo.ContractAddress` = Association contract (for example)

2. **T=1: Approve Proposal**
   - Attacker's 60% of compromised miners vote to approve
   - Proposal reaches `MinimalApprovalThreshold` and `MinimalVoteThreshold`

3. **T=2: Release Proposal**
   - Attacker (or any address) calls `Release` on the proposal
   - Parliament contract executes `ChangeMethodFeeController` via virtual inline call
   - `State.MethodFeeController.Value` immediately updated to attacker's organization

4. **T=3: Attacker Loses Miner Control**
   - Network operators detect and remove compromised miner nodes
   - Attacker no longer controls Parliament majority

**Expected Result:** Controller change should be delayed, allowing legitimate governance to cancel

**Actual Result:** Controller permanently changed to attacker's organization. Legitimate governance cannot revert without controlling attacker's organization (impossible).

**Success Condition:** `GetMethodFeeController()` returns attacker's `AuthorityInfo`, and attacker can call `SetMethodFee` while legitimate governance cannot revert the change.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L170-173)
```csharp
    private void AssertSenderAddressWith(Address address)
    {
        Assert(Context.Sender == address, "Unauthorized behavior.");
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L366-373)
```csharp
    public override Empty ChangeContractDeploymentController(AuthorityInfo input)
    {
        AssertSenderAddressWith(State.ContractDeploymentController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");
        State.ContractDeploymentController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L375-382)
```csharp
    public override Empty ChangeCodeCheckController(AuthorityInfo input)
    {
        AssertSenderAddressWith(State.CodeCheckController.Value.OwnerAddress);
        Assert(CheckOrganizationExist(input),
            "Invalid authority input.");
        State.CodeCheckController.Value = input;
        return new Empty();
    }
```
