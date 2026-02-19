### Title
No Time-Delay Mechanism for Method Fee Controller Changes Allows Immediate Malicious Fee Manipulation

### Summary
The `ChangeMethodFeeController()` function in the MultiToken contract applies controller changes immediately without any time-delay or grace period, preventing emergency response to malicious governance actions. Once a proposal to change the controller is released, the new controller can instantly set arbitrary transaction fees, potentially causing economic denial-of-service across all token operations with no immediate recourse.

### Finding Description

The `ChangeMethodFeeController()` method applies the new controller immediately upon execution, with no time-delay mechanism: [1](#0-0) 

The method directly updates `State.MethodFeeController.Value` on line 31 with no delay, pending state, or grace period. When the Parliament contract releases a proposal, it immediately executes the transaction inline: [2](#0-1) 

The proposal execution happens immediately via `Context.SendVirtualInlineBySystemContract()` on lines 138-140, with no delay between approval threshold being reached and execution. Once the new controller is active, it can immediately call `SetMethodFee()`: [3](#0-2) 

The `SetMethodFee()` method only validates that the caller is the current controller (line 18) and that fee tokens are valid (line 15), but imposes no upper limits on fee amounts beyond basic validation: [4](#0-3) 

The validation only checks `amount > 0` (line 85), allowing fees up to `long.MaxValue`. Test evidence confirms the immediate execution: [5](#0-4) 

Lines 47-52 demonstrate that immediately after `Release()` is called, the new controller is active with no delay.

### Impact Explanation

**Operational Impact - High Severity:**
- A malicious controller can immediately set exorbitant fees (up to 9,223,372,036,854,775,807 per token) for critical methods like `Transfer`, `Approve`, `TransferFrom`
- This creates instant economic denial-of-service, making all token operations prohibitively expensive or impossible
- Affects all users attempting to transact with tokens, potentially freezing the entire token economy
- Cross-contract operations requiring token transfers (consensus rewards, profit distributions, treasury operations) would fail

**No Emergency Response:**
- The only recourse is creating a new proposal to change the controller back, requiring:
  - Proposal creation
  - Gathering 2/3 miner approvals (default threshold)
  - Proposal release
- This process could take hours to days, during which the system is compromised
- No emergency response organization with expedited procedures exists for this specific attack vector

### Likelihood Explanation

**Medium Likelihood:**

**Attacker Capabilities Required:**
- Must compromise or convince 2/3 of Parliament members (default organization uses miner consensus)
- Could be achieved through social engineering, bribery, or compromise of miner keys
- Requires creating a seemingly legitimate proposal that masks malicious intent

**Attack Complexity:**
- Low complexity once governance threshold is reached
- Proposal creation is straightforward
- Execution is automatic once approved and released
- No technical barriers after governance compromise

**Feasibility Conditions:**
- Parliament default organization requires 2/3 miner approval [6](#0-5) 

- Governance attacks have historical precedent in blockchain systems
- The lack of time-delay makes detection before execution impossible

**Economic Rationality:**
- Cost: Resources needed to compromise 2/3 of governance
- Benefit: Complete control over transaction fees, potential for ransom or economic disruption
- Risk: Attack is on-chain and traceable, but damage occurs before response

### Recommendation

**Implement Time-Lock Mechanism:**

1. Add a pending controller state and activation timestamp to `TokenContractState`:
```csharp
public SingletonState<AuthorityInfo> PendingMethodFeeController { get; set; }
public SingletonState<Timestamp> ControllerActivationTime { get; set; }
```

2. Modify `ChangeMethodFeeController()` to stage changes with delay:
```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");
    
    // Stage the change with 72-hour delay
    State.PendingMethodFeeController.Value = input;
    State.ControllerActivationTime.Value = Context.CurrentBlockTime.AddHours(72);
    
    Context.Fire(new MethodFeeControllerChangeQueued 
    { 
        NewController = input,
        ActivationTime = State.ControllerActivationTime.Value 
    });
    
    return new Empty();
}
```

3. Add activation method:
```csharp
public override Empty ActivatePendingMethodFeeController(Empty input)
{
    Assert(State.PendingMethodFeeController.Value != null, "No pending controller.");
    Assert(Context.CurrentBlockTime >= State.ControllerActivationTime.Value, 
        "Activation time not reached.");
    
    State.MethodFeeController.Value = State.PendingMethodFeeController.Value;
    State.PendingMethodFeeController.Value = null;
    State.ControllerActivationTime.Value = null;
    
    return new Empty();
}
```

4. Add emergency cancellation via emergency response organization:
```csharp
public override Empty CancelPendingMethodFeeController(Empty input)
{
    var emergencyOrg = State.ParliamentContract.GetEmergencyResponseOrganizationAddress.Call(new Empty());
    Assert(Context.Sender == emergencyOrg, "Only emergency organization can cancel.");
    
    State.PendingMethodFeeController.Value = null;
    State.ControllerActivationTime.Value = null;
    
    return new Empty();
}
```

**Invariant Checks:**
- Pending controller changes must have activation time >= 72 hours in future
- Only one pending change allowed at a time
- Emergency cancellation only by designated emergency response organization
- Controller activation only after delay period expires

**Test Cases:**
- Test that controller changes are staged but not immediately active
- Test emergency cancellation by authorized organization
- Test that activation fails before delay expires
- Test multiple rapid change attempts are rejected

### Proof of Concept

**Initial State:**
- MultiToken contract deployed
- Default method fee controller is Parliament default organization
- Parliament has 5 miners with 2/3 approval threshold (4 approvals needed)

**Attack Steps:**

1. Attacker creates malicious organization with their address as controller
2. Attacker creates proposal to change method fee controller to malicious organization:
   - Target: TokenContract.ChangeMethodFeeController
   - Parameters: `{OwnerAddress: attackerOrganization, ContractAddress: ParliamentContract}`
3. Attacker convinces/compromises 4 of 5 miners to approve proposal
4. Attacker calls `ParliamentContract.Release(proposalId)`
5. **Immediate execution** - new controller takes effect in same transaction
6. Attacker immediately calls `TokenContract.SetMethodFee()` to set:
   - Transfer basic fee: 1,000,000,000 ELF
   - Approve basic fee: 1,000,000,000 ELF
7. All token operations now require exorbitant fees
8. Legitimate governance must create counter-proposal, get approvals, and release - taking hours/days

**Expected Result:** 
Time-delay prevents immediate activation, allowing emergency response

**Actual Result:**
Controller change is immediate, fees manipulated instantly, no emergency response window exists

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L13-22)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");

        State.TransactionFees[input.MethodName] = input;
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L11-37)
```csharp
    public override Empty Initialize(InitializeInput input)
    {
        Assert(!State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;

        var proposerWhiteList = new ProposerWhiteList();

        if (input.PrivilegedProposer != null)
            proposerWhiteList.Proposers.Add(input.PrivilegedProposer);

        State.ProposerWhiteList.Value = proposerWhiteList;
        var organizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = DefaultOrganizationMinimalApprovalThreshold,
                MinimalVoteThreshold = DefaultOrganizationMinimalVoteThresholdThreshold,
                MaximalAbstentionThreshold = DefaultOrganizationMaximalAbstentionThreshold,
                MaximalRejectionThreshold = DefaultOrganizationMaximalRejectionThreshold
            },
            ProposerAuthorityRequired = input.ProposerAuthorityRequired,
            ParliamentMemberProposingAllowed = true
        };
        var defaultOrganizationAddress = CreateNewOrganization(organizationInput);
        State.DefaultOrganizationAddress.Value = defaultOrganizationAddress;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/ACS1_ImplementTest.cs (L47-53)
```csharp
        var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId);
        releaseResult.TransactionResult.Error.ShouldBeNullOrEmpty();
        releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        var newMethodFeeController = await TokenContractStub.GetMethodFeeController.CallAsync(new Empty());
        newMethodFeeController.OwnerAddress.ShouldBe(organizationAddress);
    }
```
