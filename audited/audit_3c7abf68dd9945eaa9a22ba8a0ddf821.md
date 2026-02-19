### Title
Method Fees Persist After Controller Change Allowing Outgoing Controller to Set Permanent Malicious Fees

### Summary
The `ChangeMethodFeeController` function does not clear existing method fees when changing the controller, allowing a soon-to-be-replaced controller to front-run the controller change by setting malicious fees that persist indefinitely. The new controller must then create individual governance proposals to fix each affected method, causing operational disruption and potential financial harm to users.

### Finding Description

The vulnerability exists in the `ChangeMethodFeeController` implementation which only updates the controller authority without clearing the existing transaction fees state. [1](#0-0) 

The function validates authorization and the new organization, but crucially only updates `State.MethodFeeController.Value` without touching `State.TransactionFees`. 

Method fees are set via `SetMethodFee` which requires the caller to be the current controller: [2](#0-1) 

The fees are stored in the mapped state `State.TransactionFees[input.MethodName]` and retrieved by `GetMethodFee`: [3](#0-2) 

**Attack Execution Path**:

In the AElf governance model, both `SetMethodFee` and `ChangeMethodFeeController` require Parliament proposals. The critical window exists between when a `ChangeMethodFeeController` proposal is approved and when it's released. Only the proposer can release proposals: [4](#0-3) 

**Why Protections Fail**:

1. The old controller retains full `SetMethodFee` authority until the exact moment the `ChangeMethodFeeController` proposal executes
2. The old controller can create, approve, and release their own `SetMethodFee` proposals instantly since they control the organization
3. No state cleanup occurs in `ChangeMethodFeeController` - fees set by the old controller persist indefinitely
4. The same pattern exists across all ACS1 implementations, including MultiToken: [5](#0-4) 

### Impact Explanation

**Financial Harm**: Users are forced to pay inflated transaction fees until the new controller fixes them through governance. For example, if the outgoing controller sets `CreateScheme` fee from 10 ELF (default) to 1,000,000 ELF, every user calling this method loses funds.

**Operational DoS**: Extremely high fees effectively disable critical contract methods. If fees are set higher than typical user balances, the contract becomes unusable until fixed.

**Governance Overhead**: The new controller must create separate governance proposals for EACH affected method since no batch update mechanism exists. Each proposal requires:
- Creation by authorized proposer
- Approval by 2/3 of miners (default Parliament threshold)
- Release by proposer
- Multiple blocks of delay

This could take hours or days to fully remediate if many methods are affected.

**Protocol-Wide Impact**: This pattern affects all 13+ system contracts implementing ACS1 (Profit, MultiToken, Treasury, Economic, Parliament, Association, Referendum, CrossChain, Election, Vote, Consensus, Configuration, TokenHolder), amplifying the attack surface.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must BE or have COMPROMISED the current MethodFeeController organization. This is realistic in scenarios where:
- An organization is compromised right before a planned controller replacement
- Outgoing organization members execute a "scorched earth" attack when losing power
- A delayed-detection compromise where the replacement is already in progress

**Attack Complexity**: LOW for a malicious/compromised controller:
1. Detect pending `ChangeMethodFeeController` proposal (publicly visible on-chain)
2. Create `SetMethodFee` proposals for target methods (organization controls this)
3. Approve proposals instantly (organization has the votes)
4. Release proposals immediately (organization members are proposers)
5. Wait for fees to be stored in state
6. The `ChangeMethodFeeController` proposal then executes, but malicious fees persist

**Feasibility Conditions**: 
- Attack window exists between approval and release of controller change
- No time-lock or delay mechanisms prevent rapid proposal execution
- Parliament Release permission check only validates the proposer, not timing constraints [6](#0-5) 

**Detection**: The attack is visible on-chain but may not be detected until users encounter the malicious fees. By then, the controller has changed and immediate reversal requires new governance proposals.

### Recommendation

**Immediate Fix**: Add state cleanup in `ChangeMethodFeeController`:

```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");

    // Clear all existing method fees when changing controller
    // This prevents outgoing controller from setting persistent malicious fees
    State.TransactionFees.Clear();
    
    State.MethodFeeController.Value = input;
    return new Empty();
}
```

**Alternative Approach**: Implement a time-lock mechanism where method fees set within a certain period before a controller change are automatically invalidated.

**Invariant to Enforce**: A new controller should not inherit transaction fee state from the previous controller. The new controller should explicitly set all required fees.

**Test Cases**:
1. Verify `TransactionFees` mapping is empty after `ChangeMethodFeeController`
2. Verify fees set immediately before controller change do not persist
3. Verify new controller can set fees from clean state
4. Regression test for all ACS1 implementations (apply fix to all 13+ system contracts)

### Proof of Concept

**Initial State**:
- Organization A controls MethodFeeController for Profit contract
- Default fee for `CreateScheme` is 10 ELF

**Attack Sequence**:

1. **T0**: Proposer creates `ChangeMethodFeeController(Organization A → Organization B)` proposal
2. **T1**: Organization A members approve the proposal (threshold reached)
3. **T2**: Organization A detects the approved proposal and initiates attack:
   - Creates proposal: `SetMethodFee("CreateScheme", fee=1000000 ELF)`
   - Approves it instantly (they control Organization A)
   - Releases it immediately (they are the proposer)
4. **T3**: Malicious fee executes: `State.TransactionFees["CreateScheme"]` = 1000000 ELF
5. **T4**: Original proposer releases `ChangeMethodFeeController` proposal
6. **T5**: Controller changes: `State.MethodFeeController.Value` = Organization B
   - **BUT**: `State.TransactionFees["CreateScheme"]` still = 1000000 ELF (NOT cleared)

**Expected Result**: After controller change, fees should be reset/cleared or explicitly validated

**Actual Result**: Malicious fee of 1000000 ELF persists. Users calling `CreateScheme` must pay 1000000 ELF until Organization B creates, approves, and releases a new proposal to fix it (days of delay).

**Success Condition**: Call `GetMethodFee("CreateScheme")` after controller change returns 1000000 ELF instead of the expected 10 ELF default, demonstrating the persistence of malicious fees beyond the attacker's authority.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L11-20)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L22-31)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L35-59)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var methodFees = State.TransactionFees[input.Value];
        if (methodFees != null) return methodFees;

        switch (input.Value)
        {
            case nameof(CreateScheme):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
            default:
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 1_00000000 }
                    }
                };
        }
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
