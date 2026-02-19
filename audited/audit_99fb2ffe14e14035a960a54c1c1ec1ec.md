### Title
Malicious Contract Return Value Manipulation in CheckOrganizationExist Bypasses Organization Validation

### Summary
The `CheckOrganizationExist` function in all AElf system contracts makes an unchecked cross-contract call to a user-supplied contract address, allowing an attacker to deploy a malicious contract that always returns `true`, bypassing organization existence validation. This enables privilege escalation from temporary governance-controlled access to permanent direct control, eliminating all future governance oversight for critical functions like fee setting across all system contracts.

### Finding Description

**Vulnerable Code Location:** [1](#0-0) 

**Root Cause:**
The `CheckOrganizationExist` function accepts an `AuthorityInfo` parameter and makes a `Context.Call<BoolValue>` to `authorityInfo.ContractAddress` without validating that this address is a legitimate governance contract (Parliament, Association, or Referendum). The `ContractAddress` field is user-supplied input. [2](#0-1) 

**Exploitation Path:**
1. The `ChangeMethodFeeController` function requires the caller to be the current controller's `OwnerAddress`
2. Through a governance-approved proposal executed via `Release`, the organization acts as the sender
3. The attacker includes malicious `AuthorityInfo` in the proposal with `ContractAddress` pointing to their deployed contract
4. The malicious contract implements `ValidateOrganizationExist` to always return `BoolValue{Value=true}` for any input
5. `CheckOrganizationExist` calls the malicious contract and receives `true`
6. The new controller is set with `OwnerAddress` as the attacker's direct wallet address instead of a governance organization
7. Future calls to `SetMethodFee` now only check `Context.Sender == attacker's address`, bypassing all governance

**Why Existing Protections Fail:**
The authorization check on line 25 only validates that the sender is the current controller, but does not validate that the NEW controller is a legitimate governance organization. The legitimate implementations of `ValidateOrganizationExist` check `State.Organizations[input] != null`: [3](#0-2) [4](#0-3) 

However, since `ContractAddress` is attacker-controlled, they bypass this state check entirely.

**Systemic Pattern:**
This identical vulnerability exists in ALL AElf system contracts implementing ACS1: [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
1. **Privilege Escalation**: Converts temporary governance-controlled access into permanent direct control, eliminating all future governance oversight
2. **Fee Manipulation**: Attacker gains direct control over `SetMethodFee` for all contract methods
3. **Denial of Service**: Can set prohibitively high fees to effectively DoS critical system functions
4. **Economic Damage**: Can set zero fees for themselves while maintaining high fees for others, or eliminate fee revenue entirely
5. **Governance Bypass**: Breaks the fundamental invariant that controllers must be legitimate governance organizations

**Affected Systems:**
All system contracts using this pattern (Genesis, MultiToken, Economic, Treasury, Profit, Parliament, Association, Referendum, CrossChain, Consensus, Election, Vote, Configuration, TokenConverter, TokenHolder) - affecting method fee control across the entire platform.

**Severity Justification:**
CRITICAL - This vulnerability breaks a fundamental security invariant (controllers must be governance organizations), enables permanent privilege escalation, affects all critical system contracts, and allows unauthorized control over transaction fee economics.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to get ONE governance proposal approved through normal channels (Parliament 2/3+ BPs, Association multi-sig, or Referendum token vote)
- Ability to deploy a simple malicious contract with a single method

**Attack Complexity:**
LOW - The malicious contract is trivial (one method returning `true`), and the attack requires only a single approved governance proposal.

**Feasibility Conditions:**
- Governance proposal approval through social engineering, coordination with compromised/malicious governance members, or legitimate-seeming proposals
- Once executed, the attacker has permanent control without requiring further governance interaction

**Probability Assessment:**
MEDIUM-HIGH - While initial governance approval is required, this is achievable through various means (compromised keys, social engineering, malicious insiders, or legitimate-seeming proposals). The permanent nature of the exploit makes the one-time cost worthwhile for sophisticated attackers.

### Recommendation

**Immediate Fix:**
Add explicit validation that `ContractAddress` in `AuthorityInfo` must be one of the known system governance contracts:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate ContractAddress is a legitimate governance contract
    RequireGovernanceContract(authorityInfo.ContractAddress);
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}

private void RequireGovernanceContract(Address contractAddress)
{
    var isParliament = contractAddress == Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    var isAssociation = contractAddress == Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName);
    var isReferendum = contractAddress == Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    
    Assert(isParliament || isAssociation || isReferendum, "Invalid governance contract address.");
}
```

**Apply to All Affected Contracts:**
Update the pattern in all 16 affected contracts identified during investigation.

**Test Cases:**
1. Verify rejection when `ContractAddress` is not a system governance contract
2. Verify acceptance only for Parliament, Association, and Referendum contracts
3. Test with both valid and invalid organization addresses in legitimate governance contracts
4. Ensure backwards compatibility with existing valid controllers

### Proof of Concept

**Malicious Contract:**
```csharp
public class MaliciousAuthContract : SmartContract<State>
{
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        // Always return true, bypassing organization existence check
        return new BoolValue { Value = true };
    }
}
```

**Attack Sequence:**
1. **Initial State**: Economic contract has `MethodFeeController` set to Parliament default organization
2. **Deploy**: Attacker deploys `MaliciousAuthContract` at address `0xMALICIOUS`
3. **Create Proposal**: Through Parliament, create proposal calling:
   ```
   EconomicContract.ChangeMethodFeeController(
       new AuthorityInfo {
           ContractAddress = 0xMALICIOUS,
           OwnerAddress = 0xATTACKER_WALLET
       }
   )
   ```
4. **Approve**: Get proposal approved through normal governance (2/3+ BPs)
5. **Release**: Proposer calls `Release(proposalId)`, which executes with Parliament org as sender [8](#0-7) 
6. **Authorization Passes**: Line 25 check passes (sender is Parliament org)
7. **Validation Bypassed**: `CheckOrganizationExist` calls `0xMALICIOUS.ValidateOrganizationExist()` which returns `true`
8. **Controller Changed**: `State.MethodFeeController.Value` now points to attacker's direct address
9. **Permanent Control**: Attacker can now directly call `SetMethodFee` without any governance: [9](#0-8) 

**Success Condition:**
`State.MethodFeeController.Value.OwnerAddress == 0xATTACKER_WALLET` and attacker can call `SetMethodFee` without governance proposals.

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L11-20)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L71-76)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L56-60)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L116-119)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L180-185)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```
