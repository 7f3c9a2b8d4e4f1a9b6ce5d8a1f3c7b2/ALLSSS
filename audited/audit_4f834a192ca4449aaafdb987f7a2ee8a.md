### Title
Missing Emergency Recovery Mechanism for Compromised Method Fee Controller

### Summary
The Economic contract's fee controller has complete authority over method fees with no emergency override mechanism, despite Parliament having an Emergency Response Organization that is utilized by other critical contracts. If the Parliament default organization (controlling fee settings) is compromised, fees can be set to arbitrary values with no recovery path, creating a permanent DoS vector.

### Finding Description

The `SetMethodFee()` function requires authorization from `State.MethodFeeController.Value.OwnerAddress`, which defaults to Parliament's default organization. [1](#0-0) 

The controller can only be changed by the current controller itself via `ChangeMethodFeeController()`. [2](#0-1) 

The default controller initialization shows it uses Parliament's default organization address (requiring 66.67% approval). [3](#0-2) 

**Root Cause**: No emergency bypass mechanism exists. Parliament has an `EmergencyResponseOrganizationAddress` with 90% thresholds [4](#0-3)  that is used by the Election contract for critical operations like removing evil nodes. [5](#0-4) 

However, the Economic contract has no logic to allow the emergency organization to override a compromised fee controller. The Election contract demonstrates the pattern: it accepts calls from EITHER the Consensus contract OR the emergency organization. [6](#0-5) 

**Why Existing Protections Fail**:
1. Fee validation only checks `amount >= 0` with no upper bound. [7](#0-6) 
2. No timelock or delay mechanism exists for fee changes
3. The circular dependency (only current controller can change controller) means a compromised organization cannot be overridden
4. Parliament's default organization threshold is 66.67% [8](#0-7)  making it easier to compromise than the 90% emergency organization [9](#0-8) 

### Impact Explanation

**Operational Impact**: A compromised controller can set `basic_fee` to `int64.MaxValue` (9,223,372,036,854,775,807) for any method. [10](#0-9)  This renders the Economic contract completely unusable as no user can pay such fees.

**Value Extraction**: Alternatively, fees can be set to exploitative (but payable) levels to extract value from all users indefinitely.

**No Recovery Path**: Unlike the Election contract which allows emergency organization intervention, there is no fallback mechanism. Even Genesis contract updates require the same compromised organization's approval, creating a deadlock.

**Affected Parties**: All users of the Economic contract, and by extension, the entire AElf ecosystem that depends on economic functions.

**Severity**: Critical - combines permanent DoS capability with no recovery mechanism, despite emergency infrastructure existing in the system.

### Likelihood Explanation

**Attacker Capabilities Required**: Compromise of Parliament's default organization requiring collusion or control of 2/3 of block producers (66.67% threshold).

**Attack Complexity**: 
1. Compromise Parliament default organization (difficult but realistic - validator collusion, private key theft, social engineering)
2. Create proposal to call `SetMethodFee()` with extreme fees
3. Approve proposal with compromised majority
4. Execute to set fees

**Feasibility Conditions**: While compromising 2/3 of validators is non-trivial, it represents a realistic threat model that blockchain governance systems must defend against. The AElf system already acknowledges this threat by implementing the Emergency Response Organization with 90% thresholds.

**Detection Constraints**: Fee changes are transparent but immediate with no timelock, giving no window for intervention.

**Probability Reasoning**: The likelihood of compromise is medium-low, BUT the severity is amplified by complete lack of recovery mechanism. The existence of emergency infrastructure for other critical operations (Election contract) demonstrates the system's awareness of this threat model, making the omission in Economic contract a design gap rather than accepted risk.

### Recommendation

**Immediate Fix**: Add emergency organization override capability to `SetMethodFee()` and `ChangeMethodFeeController()`:

```
Assert(
    Context.Sender == State.MethodFeeController.Value.OwnerAddress || 
    Context.Sender == GetEmergencyResponseOrganizationAddress(),
    "Unauthorized to set method fee."
);
```

**Additional Protections**:
1. Implement maximum fee bounds (e.g., reasonable percentage of total supply or fixed cap)
2. Add timelock mechanism with grace period before fee changes take effect
3. Emit events for fee changes to enable monitoring
4. Consider implementing gradual fee increase limits to prevent sudden spikes

**Invariant Checks**:
- `basic_fee <= MAX_REASONABLE_FEE` constant
- Fee changes cannot exceed X% increase per time period
- Emergency organization existence check during initialization

**Test Cases**:
1. Test emergency organization can override compromised controller
2. Test fee bounds enforcement
3. Test timelock delay mechanisms
4. Test that extreme fee values are rejected

### Proof of Concept

**Initial State**:
- Parliament default organization compromised (2/3 validators colluded)
- Economic contract initialized with normal fee structure

**Attack Sequence**:
1. Compromised Parliament creates proposal to call `EconomicContract.SetMethodFee()`
2. Proposal parameters: `method_name = "Transfer"`, `basic_fee = 9223372036854775807` (int64.MaxValue)
3. Compromised majority approves proposal (passes 66.67% threshold)
4. Proposal released and executed
5. `State.TransactionFees["Transfer"]` now contains extreme fee

**Expected Result**: Emergency Response Organization (with 90% threshold of honest validators) should be able to call `SetMethodFee()` or `ChangeMethodFeeController()` to restore normal fees.

**Actual Result**: Emergency organization has no override capability. Only the compromised controller can change fees. Contract is permanently DoS'd.

**Success Condition**: All Transfer operations fail or become prohibitively expensive. No recovery mechanism available despite 90% of validators being honest and willing to intervene through emergency organization.

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L16-16)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L22-31)
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

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L50-64)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L78-87)
```csharp
    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L314-330)
```csharp
    private void CreateEmergencyResponseOrganization()
    {
        var createOrganizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 9000,
                MinimalVoteThreshold = 9000,
                MaximalAbstentionThreshold = 1000,
                MaximalRejectionThreshold = 1000
            },
            ProposerAuthorityRequired = false,
            ParliamentMemberProposingAllowed = true
        };

        State.EmergencyResponseOrganizationAddress.Value = CreateOrganization(createOrganizationInput);
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L85-88)
```csharp
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) ==
            Context.Sender || Context.Sender == GetEmergencyResponseOrganizationAddress(),
            "Only consensus contract can update candidate information.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-350)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-8)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
```

**File:** protobuf/acs1.proto (L48-53)
```text
message MethodFee {
    // The token symbol of the method fee.
    string symbol = 1;
    // The amount of fees to be charged.
    int64 basic_fee = 2;
}
```
