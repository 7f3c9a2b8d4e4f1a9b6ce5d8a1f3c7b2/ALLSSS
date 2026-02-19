### Title
Malicious Controller Bypass Through Unchecked Contract Address in ChangeMaximumMinersCountController

### Summary
The `ChangeMaximumMinersCountController` function validates organization existence by calling `ValidateOrganizationExist` on the user-provided `input.ContractAddress` without verifying it points to a legitimate governance contract. An attacker can deploy a malicious contract that always returns true, bypass proper organization validation, and gain direct ungoverned control over the maximum miners count parameter, breaking the governance invariant for critical consensus parameters.

### Finding Description

The vulnerability exists in the `ChangeMaximumMinersCountController` method: [1](#0-0) 

At line 49, the function calls `CheckOrganizationExist(input)` which is implemented as: [2](#0-1) 

The root cause is that `CheckOrganizationExist` makes a cross-contract call to `authorityInfo.ContractAddress` without any validation that this address corresponds to a legitimate governance contract (Parliament, Association, or Referendum). The code trusts whatever boolean value the provided contract returns.

An attacker can provide an `AuthorityInfo` with:
- `ContractAddress`: pointing to a malicious contract that implements a fake `ValidateOrganizationExist` method returning true
- `OwnerAddress`: the attacker's controlled address

After the controller is changed, the authorization check in `SetMaximumMinersCount` only verifies sender equality: [3](#0-2) 

This means the attacker gains direct control without any governance approval for subsequent changes.

Legitimate governance contracts properly validate organizations by checking state storage: [4](#0-3) [5](#0-4) 

However, the malicious contract bypasses this by returning true unconditionally.

### Impact Explanation

**Governance Bypass**: The vulnerability enables an attacker to permanently bypass the governance model for the `MaximumMinersCount` parameter. Once the malicious controller is set, the attacker can call `SetMaximumMinersCount` directly without any multi-signature approval, voting, or proposal process that legitimate governance contracts require.

**Consensus Integrity**: The attacker can arbitrarily manipulate the maximum miners count, which affects the miner schedule calculation: [6](#0-5) 

This could be used to:
- Limit miners to artificially small numbers, centralizing the network
- Set unreasonably large values, affecting consensus performance
- Manipulate election rewards and voting power distribution

**Protocol-Wide Impact**: The same vulnerability pattern exists across multiple system contracts (Genesis, MultiToken, CrossChain, etc.) that use `CheckOrganizationExist` without validating the contract address, potentially affecting all governance-controlled parameters system-wide.

**Severity**: High - breaks the critical invariant that consensus parameters must be governed by proper organizational consensus, enabling ungoverned control over a core protocol parameter.

### Likelihood Explanation

**Preconditions**: The attacker must first obtain approval from the current controller (initially Parliament's default organization) to execute `ChangeMaximumMinersCountController`. This requires miner consensus.

**Attack Complexity**: Moderate
1. Deploy a malicious contract with a fake `ValidateOrganizationExist` method
2. Create a Parliament proposal to call `ChangeMaximumMinersCountController` with the malicious `AuthorityInfo`
3. Obtain miner approval (through social engineering, disguising intent, or compromised keys)
4. Execute the proposal
5. Gain permanent direct control over `SetMaximumMinersCount`

**Feasibility Conditions**: While obtaining initial Parliament approval is a barrier, it's realistic because:
- Proposals may not clearly reveal the malicious contract's behavior
- Miners may approve based on trust or insufficient code review
- Alternative scenario: If an Association or Referendum organization becomes controller first, compromising fewer members may suffice
- Once achieved, the attacker retains control indefinitely

**Detection Constraints**: The malicious contract appears legitimate until its `ValidateOrganizationExist` method is called. The governance bypass only becomes apparent after the controller change is complete.

**Probability**: Medium-to-High given the attack enables permanent ungoverned control after a single successful social engineering or compromise event.

### Recommendation

**Immediate Fix**: Validate that `input.ContractAddress` is a registered system contract before accepting it:

Add a validation step in `ChangeMaximumMinersCountController`:
```csharp
public override Empty ChangeMaximumMinersCountController(AuthorityInfo input)
{
    RequiredMaximumMinersCountControllerSet();
    AssertSenderAddressWith(State.MaximumMinersCountController.Value.OwnerAddress);
    
    // NEW: Validate contract address is a known governance contract
    var isValidGovernanceContract = IsKnownGovernanceContract(input.ContractAddress);
    Assert(isValidGovernanceContract, "Contract address must be a registered governance contract.");
    
    var organizationExist = CheckOrganizationExist(input);
    Assert(organizationExist, "Invalid authority input.");
    
    State.MaximumMinersCountController.Value = input;
    return new Empty();
}

private bool IsKnownGovernanceContract(Address contractAddress)
{
    EnsureParliamentContractAddressSet();
    EnsureAssociationContractAddressSet();
    EnsureReferendumContractAddressSet();
    
    return contractAddress == State.ParliamentContract.Value ||
           contractAddress == State.AssociationContract.Value ||
           contractAddress == State.ReferendumContract.Value;
}
```

**System-Wide Fix**: Apply the same validation to all controller change methods across Genesis, MultiToken, CrossChain, and other contracts using `CheckOrganizationExist`.

**Test Cases**: Add tests verifying:
- Rejection of non-governance contract addresses
- Rejection of malicious contracts returning true
- Acceptance only of Parliament/Association/Referendum addresses
- Verification that organizations actually exist in the legitimate contracts

### Proof of Concept

**Initial State**:
- MaximumMinersCountController is Parliament's default organization
- Attacker deploys MaliciousContract with:
```csharp
public override BoolValue ValidateOrganizationExist(Address input)
{
    return new BoolValue { Value = true };
}
```

**Attack Sequence**:

1. Attacker creates Parliament proposal calling:
   - `ChangeMaximumMinersCountController(new AuthorityInfo { ContractAddress = MaliciousContract, OwnerAddress = AttackerAddress })`

2. Miners approve and release the proposal (social engineering/insufficient review)

3. `ChangeMaximumMinersCountController` executes:
   - Line 48: Sender check passes (Parliament organization)
   - Line 49: `CheckOrganizationExist` calls MaliciousContract
   - MaliciousContract returns true
   - Line 52: Controller updated to attacker's AuthorityInfo

4. Attacker directly calls:
   - `SetMaximumMinersCount(new Int32Value { Value = 1 })`
   - Line 17 check passes (Sender == AttackerAddress)
   - Maximum miners count changed to 1 without any governance

**Expected Result**: Transaction should fail with "Contract address must be a registered governance contract."

**Actual Result**: Controller successfully changed to attacker's address, enabling direct ungoverned manipulation of maximum miners count.

**Success Condition**: Attacker can repeatedly call `SetMaximumMinersCount` with arbitrary values without any proposal/voting/multi-sig approval.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L17-18)
```csharp
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L45-54)
```csharp
    public override Empty ChangeMaximumMinersCountController(AuthorityInfo input)
    {
        RequiredMaximumMinersCountControllerSet();
        AssertSenderAddressWith(State.MaximumMinersCountController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MaximumMinersCountController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L72-78)
```csharp
    public override Int32Value GetMaximumMinersCount(Empty input)
    {
        return new Int32Value
        {
            Value = Math.Min(GetAutoIncreasedMinersCount(), State.MaximumMinersCount.Value)
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L83-88)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```
