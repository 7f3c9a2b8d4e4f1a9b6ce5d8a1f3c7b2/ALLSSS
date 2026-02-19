### Title
Authorization Bypass in Contract Update Proposals via Self-Authorization Check

### Summary
The `AssertAuthorityByContractInfo` function contains a flawed authorization check that allows any user to propose updates to contracts whose author is set to the Genesis contract address (Context.Self). This occurs when contracts are deployed by non-whitelisted users, as their author is automatically set to Context.Self, effectively allowing anyone to propose malicious contract updates rather than restricting this right to the original deployer.

### Finding Description

The vulnerability exists in the authorization check at: [1](#0-0) 

This function is called from `ProposeUpdateContract` to verify authorization before allowing a contract update proposal: [2](#0-1) 

The root cause lies in the `DecideNonSystemContractAuthor` function, which sets the contract author to `Context.Self` (the Genesis contract address) when the deployer is not in the proposer whitelist: [3](#0-2) 

When a contract is deployed via the standard flow, this author decision is applied: [4](#0-3) 

The contract's author field is then stored in ContractInfo: [5](#0-4) 

**Why the protection fails:** When `contractInfo.Author == Context.Self` evaluates to true (which happens for all contracts deployed by non-whitelisted users), the assertion passes regardless of who `Context.Sender` is. This means ANY user can propose updates to these contracts, not just the original deployer.

### Impact Explanation

**Authorization Bypass:** Any user on the network can propose updates to contracts deployed by non-whitelisted users, completely bypassing the intended restriction that only the contract author should be able to propose updates.

**Loss of Ownership Control:** Original deployers lose their exclusive right to propose updates to their own contracts. This violates fundamental ownership principles and creates confusion about contract governance.

**Social Engineering Attack Vector:** Malicious actors can propose harmful contract updates with malicious code, relying on governance reviewers to catch the attack. This significantly increases the attack surface by allowing unlimited malicious proposals that governance must review and reject.

**Inconsistent Security Model:** Creates two classes of contracts with different security properties - those deployed by whitelisted users (secure) vs. non-whitelisted users (vulnerable) - leading to unpredictable security behavior.

**Affected parties:** All non-whitelisted contract deployers and users of their contracts, potentially representing the majority of dApp developers on the platform.

### Likelihood Explanation

**Reachable Entry Point:** The `ProposeUpdateContract` function is a public method callable by any user. [6](#0-5) 

**Feasible Preconditions:** 
- Production networks have `ContractDeploymentAuthorityRequired` set to true (standard configuration)
- Contracts deployed by non-whitelisted users automatically have their author set to Context.Self
- No special permissions required for the attacker

**Execution Practicality:** The exploit requires only a single transaction calling `ProposeUpdateContract` with the target contract address and malicious code. No complex state manipulation or timing requirements exist.

**Detection Constraints:** While malicious proposals still require governance approval, the sheer volume of unauthorized proposals that can be created makes it harder for governance to effectively review all submissions, increasing the chance that malicious code slips through.

**Probability:** HIGH - This condition is triggered by default for all contracts deployed through the standard process by non-whitelisted users, which is the common case for third-party dApp developers.

### Recommendation

**Immediate Fix:** Modify `AssertAuthorityByContractInfo` to remove the self-authorization bypass and only check if the caller matches the contract author:

```csharp
private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
{
    Assert(address == contractInfo.Author, "No permission.");
}
```

**Alternative Solution:** If contracts owned by the Genesis contract are intended to be governable by anyone, implement explicit tracking of the original proposer in ContractInfo and add a separate authorization check:

```csharp
private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
{
    // For contracts owned by genesis, check original proposer
    if (contractInfo.Author == Context.Self)
    {
        Assert(contractInfo.OriginalProposer == address, "No permission.");
    }
    else
    {
        Assert(address == contractInfo.Author, "No permission.");
    }
}
```

**Add invariant validation:** Ensure that contract update proposals are only accepted from the legitimate author or original proposer, never from arbitrary addresses.

**Test cases to add:**
1. Verify non-whitelisted deployer can propose updates to their own contract
2. Verify non-whitelisted deployer A cannot propose updates to non-whitelisted deployer B's contract
3. Verify whitelisted deployers maintain exclusive update rights
4. Add negative test cases for unauthorized update attempts

### Proof of Concept

**Initial State:**
- Network has `ContractDeploymentAuthorityRequired = true`
- Alice (address 0xAAA) is NOT in the deployment proposer whitelist
- Bob (address 0xBBB) is a malicious actor
- Alice has deployed ContractX through the governance proposal process

**Step 1: Verify Alice's contract has vulnerable author field**
```
Query: GetContractInfo(ContractX)
Result: ContractInfo.Author = BasicContractZeroAddress (Context.Self)
```

**Step 2: Bob proposes malicious update (unauthorized)**
```
Transaction: Bob calls ProposeUpdateContract(
    Address: ContractX,
    Code: <malicious_bytecode>,
    ContractOperation: null
)

Expected: Transaction should FAIL with "No permission"
Actual: Transaction SUCCEEDS and creates proposal

Reason: AssertAuthorityByContractInfo evaluates:
  - contractInfo.Author == Context.Self → TRUE (both are BasicContractZeroAddress)
  - Assertion passes for Bob despite Bob ≠ Alice
```

**Step 3: Verify unauthorized proposal was created**
```
Event: ContractProposed { ProposedContractInputHash: <hash> }
Status: Proposal is now pending governance approval
```

**Success Condition:** Bob was able to create a proposal to update Alice's contract despite having no authorization, demonstrating complete bypass of the author-based access control.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L42-52)
```csharp
        var info = new ContractInfo
        {
            SerialNumber = serialNumber,
            Author = author,
            Category = category,
            CodeHash = codeHash,
            IsSystemContract = isSystemContract,
            Version = 1,
            IsUserContract = isUserContract,
            Deployer = deployer
        };
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L241-244)
```csharp
    private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
    {
        Assert(contractInfo.Author == Context.Self || address == contractInfo.Author, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L257-266)
```csharp
    private Address DecideNonSystemContractAuthor(Address proposer, Address sender)
    {
        if (!State.ContractDeploymentAuthorityRequired.Value)
            return sender;

        var contractDeploymentController = State.ContractDeploymentController.Value;
        var isProposerInWhiteList = ValidateProposerAuthority(contractDeploymentController.ContractAddress,
            contractDeploymentController.OwnerAddress, proposer);
        return isProposerInWhiteList ? proposer : Context.Self;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L175-176)
```csharp
    public override Hash ProposeUpdateContract(ContractUpdateInput input)
    {
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L183-183)
```csharp
        AssertAuthorityByContractInfo(info, Context.Sender);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L317-321)
```csharp
        var address =
            DeploySmartContract(null, input.Category, input.Code.ToByteArray(), false,
                DecideNonSystemContractAuthor(contractProposingInput?.Proposer, Context.Sender), false,
                input.ContractOperation?.Deployer, input.ContractOperation?.Salt);
        return address;
```
