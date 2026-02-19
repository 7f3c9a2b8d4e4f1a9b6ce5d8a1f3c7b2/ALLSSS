### Title
Missing Input Validation in SetContractProposalExpirationTimePeriod Allows DoS of Contract Deployment System

### Summary
The `SetContractProposalExpirationTimePeriod` method lacks validation to ensure the expiration time period is positive, allowing negative or overflow-inducing values to be set. This breaks the proposal timing logic, causing all contract deployment and update proposals to fail validation, resulting in a complete denial of service of the contract lifecycle management system.

### Finding Description

The `SetContractProposalExpirationTimePeriod` method in `BasicContractZero.cs` accepts an `int32` value without any validation: [1](#0-0) 

This contrasts with the similar `SetCodeCheckProposalExpirationTimePeriod` method which validates the input must be positive: [2](#0-1) 

The unvalidated value is retrieved by `GetCurrentContractProposalExpirationTimePeriod`: [3](#0-2) 

And used to set proposal expiration times via `AddSeconds()`: [4](#0-3) 

When negative values are used, the resulting `ExpiredTime` is in the past. When proposals are created in Parliament, they are validated by `CheckProposalNotExpired`: [5](#0-4) 

This validation requires `Context.CurrentBlockTime < proposal.ExpiredTime`. Proposals with past expiration times fail this check: [6](#0-5) 

The proposal creation in `ProposeNewContract` uses this expiration time: [7](#0-6) 

### Impact Explanation

**Negative Values**: Setting a negative expiration period (e.g., -1000000) causes all contract deployment and update proposals to fail immediately because:
1. The `ExpiredTime` is calculated as past time
2. Parliament's `CheckProposalNotExpired` validation rejects proposals with past expiration
3. All calls to `ProposeNewContract` and `ProposeUpdateContract` fail
4. Complete DoS of the contract lifecycle management system

**Extremely Large Values**: Setting values approaching `INT32_MAX` (2,147,483,647 seconds) can cause:
1. Timestamp overflow when added to `CurrentBlockTime` via `AddSeconds()`
2. The `AddSeconds` method performs checked arithmetic: [8](#0-7) 
3. Overflow throws an exception, failing all proposal creation calls

This breaks the **Authorization & Governance** critical invariant requiring correct "proposal lifetime/expiration" functionality.

### Likelihood Explanation

**Attacker Capabilities**: Requires control of the `ContractDeploymentController` organization (typically Parliament) to call the setter method: [9](#0-8) 

**Attack Complexity**: Low - a single governance proposal can set the value.

**Feasibility**: While this requires governance approval, the vulnerability represents a **missing input validation** issue rather than relying on governance compromise. Even trusted roles should not be able to set values that violate system invariants. The existence of validation in the parallel method `SetCodeCheckProposalExpirationTimePeriod` demonstrates this protection is expected but missing.

**Detection**: Setting invalid values would immediately cause observable failures in contract deployment, making detection straightforward but damage already done.

### Recommendation

Add input validation to `SetContractProposalExpirationTimePeriod` matching the validation in `SetCodeCheckProposalExpirationTimePeriod`:

```csharp
public override Empty SetContractProposalExpirationTimePeriod(SetContractProposalExpirationTimePeriodInput input)
{
    AssertSenderAddressWith(State.ContractDeploymentController.Value.OwnerAddress);
    Assert(input.ExpirationTimePeriod > 0, "Invalid expiration time period.");
    State.ContractProposalExpirationTimePeriod.Value = input.ExpirationTimePeriod;
    return new Empty();
}
```

Add test cases to verify:
1. Negative values are rejected with appropriate error message
2. Zero value is rejected
3. Reasonable positive values are accepted
4. Extremely large values that could cause overflow are rejected

### Proof of Concept

**Initial State**: 
- Genesis contract initialized with default `ContractProposalExpirationTimePeriod` of 259200 seconds
- Parliament organization exists as ContractDeploymentController

**Attack Steps**:
1. Create Parliament proposal to call `SetContractProposalExpirationTimePeriod` with `ExpirationTimePeriod = -1000000`
2. Approve and release the proposal
3. Attempt to call `ProposeNewContract` with any valid contract code

**Expected Result**: Contract proposal should be created successfully

**Actual Result**: Proposal creation fails with "Invalid proposal." error because:
- `ExpiredTime = CurrentBlockTime.AddSeconds(-1000000)` sets time to the past
- Parliament's `CheckProposalNotExpired` validation fails
- Transaction fails, DoS achieved

**Success Condition**: All subsequent contract deployment/update operations fail until the parameter is corrected through another governance proposal.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L130-165)
```csharp
        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();

        if (input.ContractOperation != null)
        {
            ValidateContractOperation(input.ContractOperation, 0, codeHash);
            
            // Remove one time signer if exists. Signer is only needed for validating signature.
            RemoveOneTimeSigner(input.ContractOperation.Deployer);
            
            AssertContractAddressAvailable(input.ContractOperation.Deployer, input.ContractOperation.Salt);
        }

        // Create proposal for deployment
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput = new CreateProposalInput
            {
                ToAddress = Context.Self,
                ContractMethodName =
                    nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.ProposeContractCodeCheck),
                Params = new ContractCodeCheckInput
                {
                    ContractInput = input.ToByteString(),
                    CodeCheckReleaseMethod = nameof(DeploySmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = input.Category,
                    IsSystemContract = false
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput.ToByteString());
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L394-399)
```csharp
    public override Empty SetContractProposalExpirationTimePeriod(SetContractProposalExpirationTimePeriodInput input)
    {
        AssertSenderAddressWith(State.ContractDeploymentController.Value.OwnerAddress);
        State.ContractProposalExpirationTimePeriod.Value = input.ExpirationTimePeriod;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L401-407)
```csharp
    public override Empty SetCodeCheckProposalExpirationTimePeriod(Int32Value input)
    {
        AssertSenderAddressWith(State.ContractDeploymentController.Value.OwnerAddress);
        Assert(input.Value > 0, "Invalid expiration time period.");
        State.CodeCheckProposalExpirationTimePeriod.Value = input.Value;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L208-214)
```csharp
        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();
        State.ContractProposingInputMap[proposedContractInputHash] = new ContractProposingInput
        {
            Proposer = Context.Sender,
            Status = ContractProposingInputStatus.Proposed,
            ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
        };
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L282-287)
```csharp
    private int GetCurrentContractProposalExpirationTimePeriod()
    {
        return State.ContractProposalExpirationTimePeriod.Value == 0
            ? ContractProposalExpirationTimePeriod
            : State.ContractProposalExpirationTimePeriod.Value;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L157-166)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = CheckProposalNotExpired(proposal);
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L177-180)
```csharp
    private bool CheckProposalNotExpired(ProposalInfo proposal)
    {
        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** src/AElf.CSharp.Core/Extension/TimestampExtensions.cs (L28-31)
```csharp
    public static Timestamp AddSeconds(this Timestamp timestamp, long seconds)
    {
        return timestamp + new Duration { Seconds = seconds };
    }
```
