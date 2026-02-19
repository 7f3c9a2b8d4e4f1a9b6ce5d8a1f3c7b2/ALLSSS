### Title
User Contract Authorization Bypass via isUserContract Flag Manipulation During Updates

### Summary
Contract authors can bypass the stricter miner-based authorization model for user contracts by updating them through `ProposeUpdateContract` instead of `UpdateUserSmartContract`. This flips the `isUserContract` flag from `true` to `false`, allowing future updates to bypass the `AssertCurrentMiner()` requirement and use Parliament governance instead, fundamentally altering the contract's governance model without proper authorization.

### Finding Description

**Root Cause:**

The vulnerability exists in the contract update flow where `ProposeUpdateContract` does not validate or preserve the `isUserContract` flag during updates. [1](#0-0) 

At line 215, `ProposeUpdateContract` preserves `IsSystemContract` from the original contract info, but there is **no preservation or validation** of the `isUserContract` flag. The method routes to `UpdateSmartContract` via the `CodeCheckReleaseMethod` parameter. [2](#0-1) 

The public `UpdateSmartContract` method at line 334 calls the private helper with `isUserContract` hardcoded to `false`, regardless of the original contract's type. [3](#0-2) 

The helper method at line 110 unconditionally overwrites `info.IsUserContract = isUserContract`, permanently flipping the flag from `true` to `false`.

**Why Existing Protections Fail:**

Line 183 only checks `AssertAuthorityByContractInfo(info, Context.Sender)`, which validates the author but does not prevent user contracts from being updated through the wrong path. [4](#0-3) 

There is no validation that ensures user contracts must use the `UpdateUserSmartContract` path or that the `isUserContract` flag cannot be changed.

### Impact Explanation

**Authorization Bypass:**

User contracts are designed to require miner approval for updates through `ReleaseApprovedUserSmartContract`: [5](#0-4) 

Line 485 enforces `AssertCurrentMiner()`, ensuring only current miners can release user contract updates. This is a stricter authorization model than regular contracts.

Once the `isUserContract` flag is flipped to `false`, subsequent updates bypass this requirement and instead use `ReleaseCodeCheckedContract`: [6](#0-5) 

This method only requires the proposer to match (line 299) and does **not** require miner authorization, allowing Parliament governance instead.

**Who Is Affected:**

- User contract authors can unilaterally weaken their contract's governance model
- Users/stakeholders who deployed contracts expecting miner-based governance
- The protocol's governance integrity, as contract types become mutable

**Severity Justification:**

This is a **High** severity vulnerability because it:
1. Allows unauthorized governance model changes
2. Permanently alters the authorization requirements for contract updates
3. Can be exploited by any user contract author
4. Violates the invariant that contract types should remain consistent

### Likelihood Explanation

**Attacker Capabilities:**
- Must be the author of a user contract (obtainable by deploying a user contract)
- Requires Parliament approval for the update proposal (standard governance process)

**Attack Complexity:**
Low - the attacker simply calls `ProposeUpdateContract` instead of `UpdateUserSmartContract`, both of which are public methods accessible to contract authors.

**Feasibility Conditions:**
1. Deploy a user contract via `DeployUserSmartContract`
2. Call `ProposeUpdateContract` with the contract address and new code
3. Obtain Parliament approval (same as regular contract updates)
4. Code check passes
5. `UpdateSmartContract` executes, flipping `isUserContract` to `false`

**Detection Constraints:**
The flag change happens silently within the state update. There is no event or validation that would alert anyone that the contract type has changed.

**Probability:**
High - any motivated contract author can execute this attack with minimal cost (only governance approval needed, which is the standard process for contract updates).

### Recommendation

**Code-Level Mitigation:**

Add validation in `ProposeUpdateContract` to prevent updating user contracts through this path:

```csharp
public override Hash ProposeUpdateContract(ContractUpdateInput input)
{
    // ... existing code ...
    var info = State.ContractInfos[contractAddress];
    Assert(info != null, "Contract not found.");
    
    // ADD THIS CHECK:
    Assert(!info.IsUserContract, "User contracts must use UpdateUserSmartContract.");
    
    AssertAuthorityByContractInfo(info, Context.Sender);
    // ... rest of method ...
}
```

**Alternative/Additional Fix:**

Preserve the `isUserContract` flag in the `ContractCodeCheckInput` (similar to how `IsSystemContract` is preserved at line 215) and pass it through to the update method: [7](#0-6) 

Then modify the helper to preserve the original flag value instead of overwriting it.

**Invariant Checks to Add:**
1. User contracts (isUserContract = true) can only be updated via `UpdateUserSmartContract`
2. The `isUserContract` flag cannot be changed after deployment
3. Add event emission when contract flags are modified (for auditability)

**Test Cases:**
1. Verify that calling `ProposeUpdateContract` on a user contract fails
2. Verify that `UpdateUserSmartContract` maintains `isUserContract = true`
3. Verify that non-user contracts cannot use `UpdateUserSmartContract`
4. Test that the authorization model remains consistent after updates

### Proof of Concept

**Initial State:**
- User deploys a contract via `DeployUserSmartContract` with `category = 0` and `code = <contract_code>`
- Contract is deployed with `isUserContract = true`
- Verify via `GetContractInfo(address)` that `isUserContract == true`

**Attack Sequence:**

1. **Author calls `ProposeUpdateContract`:**
   - Input: `ContractUpdateInput { address = <user_contract_address>, code = <new_code> }`
   - Passes authorization check at line 183 (author has permission)
   - Creates proposal with `CodeCheckReleaseMethod = "UpdateSmartContract"` (line 212)
   - Proposal created successfully

2. **Parliament approves proposal:**
   - Standard governance flow via `ContractDeploymentController`
   - Proposal moves to code check stage

3. **Code check passes:**
   - Code checker approves the contract code
   - Proposal becomes executable

4. **`UpdateSmartContract` executes:**
   - Called at line 324 with `input.Address = <user_contract_address>`
   - Line 334 calls helper with `isUserContract = false` (hardcoded)
   - Helper line 110 sets `info.IsUserContract = false`
   - Contract updated successfully

**Expected vs Actual Result:**

**Expected:** User contract maintains `isUserContract = true`, future updates require miner approval via `ReleaseApprovedUserSmartContract`

**Actual:** User contract now has `isUserContract = false`, future updates only require Parliament approval via `ReleaseCodeCheckedContract`, bypassing miner authorization requirement

**Success Condition:**
Verify via `GetContractInfo(address)` that `isUserContract` has changed from `true` to `false`, and subsequent updates can use the `ProposeUpdateContract` → `ReleaseCodeCheckedContract` path without miner approval.

### Notes

The vulnerability demonstrates a critical gap in contract type immutability enforcement. While `IsSystemContract` is carefully preserved during updates, the `isUserContract` flag is not, allowing contract authors to fundamentally alter their contract's governance model post-deployment. This violates the principle that contract authorization models should be deterministic and immutable based on their deployment type.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L175-232)
```csharp
    public override Hash ProposeUpdateContract(ContractUpdateInput input)
    {
        var proposedContractInputHash = CalculateHashFromInput(input);
        RegisterContractProposingData(proposedContractInputHash);

        var contractAddress = input.Address;
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        AssertAuthorityByContractInfo(info, Context.Sender);
        AssertContractVersion(info.ContractVersion, input.Code, info.Category);

        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        AssertContractNotExists(codeHash);

        Assert((input.Address == Context.Self || info.SerialNumber > 0) && input.ContractOperation == null ||
               info.SerialNumber == 0 && input.ContractOperation != null, "Not compatible.");

        if (input.ContractOperation != null)
        {
            ValidateContractOperation(input.ContractOperation, info.Version, codeHash);
            RemoveOneTimeSigner(input.ContractOperation.Deployer);
            AssertSameDeployer(input.Address, input.ContractOperation.Deployer);
        }

        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();

        // Create proposal for contract update
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
                    CodeCheckReleaseMethod = nameof(UpdateSmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = info.Category,
                    IsSystemContract = info.IsSystemContract
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput);

        Context.Fire(new ContractProposed
        {
            ProposedContractInputHash = proposedContractInputHash
        });

        return proposedContractInputHash;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L292-306)
```csharp
    public override Empty ReleaseCodeCheckedContract(ReleaseContractInput input)
    {
        var contractProposingInput = State.ContractProposingInputMap[input.ProposedContractInputHash];

        Assert(
            contractProposingInput != null &&
            contractProposingInput.Status == ContractProposingInputStatus.CodeCheckProposed &&
            contractProposingInput.Proposer == Context.Sender, "Invalid contract proposing status.");
        contractProposingInput.Status = ContractProposingInputStatus.CodeChecked;
        State.ContractProposingInputMap[input.ProposedContractInputHash] = contractProposingInput;
        var codeCheckController = State.CodeCheckController.Value;
        Context.SendInline(codeCheckController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release), input.ProposalId);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L324-337)
```csharp
    public override Address UpdateSmartContract(ContractUpdateInput input)
    {
        var contractAddress = input.Address;
        var info = State.ContractInfos[contractAddress];
        RequireSenderAuthority(State.CodeCheckController.Value?.OwnerAddress);
        var inputHash = CalculateHashFromInput(input);

        if (!TryClearContractProposingData(inputHash, out _))
            Assert(Context.Sender == info.Author, "No permission.");

        UpdateSmartContract(contractAddress, input.Code.ToByteArray(), info.Author, false);

        return contractAddress;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L476-493)
```csharp
    public override Empty ReleaseApprovedUserSmartContract(ReleaseContractInput input)
    {
        var contractProposingInput = State.ContractProposingInputMap[input.ProposedContractInputHash];

        Assert(
            contractProposingInput != null &&
            contractProposingInput.Status == ContractProposingInputStatus.CodeCheckProposed &&
            contractProposingInput.Proposer == Context.Self, "Invalid contract proposing status.");

        AssertCurrentMiner();

        contractProposingInput.Status = ContractProposingInputStatus.CodeChecked;
        State.ContractProposingInputMap[input.ProposedContractInputHash] = contractProposingInput;
        var codeCheckController = State.CodeCheckController.Value;
        Context.SendInline(codeCheckController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release), input.ProposalId);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L98-144)
```csharp
    private void UpdateSmartContract(Address contractAddress, byte[] code, Address author, bool isUserContract)
    {
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        Assert(author == info.Author, "No permission.");

        var oldCodeHash = info.CodeHash;
        var newCodeHash = HashHelper.ComputeFrom(code);
        Assert(oldCodeHash != newCodeHash, "Code is not changed.");
        AssertContractNotExists(newCodeHash);

        info.CodeHash = newCodeHash;
        info.IsUserContract = isUserContract;
        info.Version++;

        var reg = new SmartContractRegistration
        {
            Category = info.Category,
            Code = ByteString.CopyFrom(code),
            CodeHash = newCodeHash,
            IsSystemContract = info.IsSystemContract,
            Version = info.Version,
            ContractAddress = contractAddress,
            IsUserContract = isUserContract
        };

        var contractInfo = Context.UpdateSmartContract(contractAddress, reg, null, info.ContractVersion);
        Assert(contractInfo.IsSubsequentVersion,
            $"The version to be deployed is lower than the effective version({info.ContractVersion}), please correct the version number.");

        info.ContractVersion = contractInfo.ContractVersion;
        reg.ContractVersion = info.ContractVersion;

        State.ContractInfos[contractAddress] = info;
        State.SmartContractRegistrations[reg.CodeHash] = reg;

        Context.Fire(new CodeUpdated
        {
            Address = contractAddress,
            OldCodeHash = oldCodeHash,
            NewCodeHash = newCodeHash,
            Version = info.Version,
            ContractVersion = info.ContractVersion
        });

        Context.LogDebug(() => "BasicContractZero - update success: " + contractAddress.ToBase58());
    }
```
