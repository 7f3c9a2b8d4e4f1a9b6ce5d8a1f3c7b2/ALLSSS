# Audit Report

## Title
Permanent Contract Lock Due to Missing Null/Empty Address Validation in SetContractAuthor

## Summary
The `SetContractAuthor()` function in BasicContractZero lacks input validation to prevent setting the contract author to a null or empty address. Once triggered, this creates a permanent denial-of-service condition where the contract becomes un-updatable through all update mechanisms, with no recovery path available.

## Finding Description

The `SetContractAuthor()` method directly assigns the input without validating that the new author address is non-null and non-empty: [1](#0-0) 

This violates the defensive validation pattern used consistently throughout the codebase. The `SetSigner()` method in the same contract correctly validates address inputs: [2](#0-1) 

Once `info.Author` becomes null, all contract update mechanisms become permanently blocked:

**1. ProposeUpdateContract path fails:**

The method requires author authorization via `AssertAuthorityByContractInfo()`: [3](#0-2) 

This assertion checks: [4](#0-3) 

When `contractInfo.Author` is null, both conditions fail (`null == Context.Self` is false since `Context.Self` is never null, and `Context.Sender == null` is false since transaction senders cannot be null). The assertion fails with "No permission."

**2. UpdateUserSmartContract path fails:** [5](#0-4) 

When `info.Author` is null, the equality check `Context.Sender == null` always evaluates to false.

**3. UpdateSmartContract path fails:** [6](#0-5) 

The private helper also validates the author: [7](#0-6) 

Even if both are null, governance proposals cannot be created because `ProposeUpdateContract` fails first.

**4. SetContractAuthor itself cannot fix the issue** - it has the same permission check that fails when author is null.

The protobuf `Address` type is a message type (class in C#) and can be null: [8](#0-7) 

The `SetContractAuthorInput` message definition confirms both fields are optional protobuf messages: [9](#0-8) 

In protobuf3, all fields are optional by default - if `new_author` is not explicitly set when constructing the message, it defaults to null.

## Impact Explanation

This vulnerability creates a **permanent denial-of-service** condition with HIGH severity:

1. **Irreversible Impact**: Once the author is set to null, the contract becomes permanently un-updatable. No entity can ever modify the contract code again.

2. **Critical Protocol Feature Broken**: Contract updates are essential for fixing bugs, patching security vulnerabilities, and adding features. This capability is completely eliminated.

3. **No Recovery Mechanism**: Even governance proposals cannot fix this because `ProposeUpdateContract` requires author authorization before creating a proposal, creating a circular dependency.

4. **Wide Scope**: This affects both system contracts (critical chain infrastructure) and user contracts. If a system contract's author is accidentally nullified, the entire chain's ability to fix critical issues in that contract is eliminated.

5. **Authorization Invariant Violated**: The contract governance model assumes the author can always propose updates. This assumption is permanently broken.

## Likelihood Explanation

The likelihood is **MEDIUM** for the following reasons:

**Realistic Trigger Scenarios:**
- **Protobuf default behavior**: In protobuf3, if the `new_author` field is not explicitly set during message construction, it defaults to null
- **Tooling bugs**: Contract management tools or scripts may incorrectly construct the protobuf message
- **Developer error**: Incorrect message construction during routine contract administration

**Evidence of Known Risk:**
The existence of validation in `SetSigner()` but its absence in `SetContractAuthor()` suggests this was an oversight. The codebase demonstrates awareness that null/empty addresses require explicit validation, making the missing check in this critical function particularly concerning.

**Low Attack Complexity:**
- Only requires a single transaction from the legitimate contract author
- No governance approval or multi-signature needed
- Straightforward to trigger accidentally

**Mitigating Factors:**
- Requires the legitimate author to make the call
- Not exploitable by external attackers

**Aggravating Factors:**
- Permanent and catastrophic consequences make even a single accidental occurrence critical
- Many contracts in the ecosystem could be simultaneously vulnerable
- The operational nature of contract management makes accidental triggers realistic

## Recommendation

Add input validation to `SetContractAuthor()` consistent with the pattern used in `SetSigner()`:

```csharp
public override Empty SetContractAuthor(SetContractAuthorInput input)
{
    Assert(input != null && input.NewAuthor != null && 
           !input.NewAuthor.Value.IsNullOrEmpty(), "Invalid input.");
    
    var info = State.ContractInfos[input.ContractAddress];
    Assert(info != null, "Contract not found.");
    var oldAuthor = info.Author;
    Assert(Context.Sender == info.Author, "No permission.");
    info.Author = input.NewAuthor;
    State.ContractInfos[input.ContractAddress] = info;
    Context.Fire(new AuthorUpdated()
    {
        Address = input.ContractAddress,
        OldAuthor = oldAuthor,
        NewAuthor = input.NewAuthor
    });

    return new Empty();
}
```

This validation ensures that:
1. The input message is not null
2. The new author address is not null
3. The new author address has a non-empty `Value` property

## Proof of Concept

```csharp
[Fact]
public async Task SetContractAuthor_NullAddress_ShouldRevertAndPreventPermanentLock()
{
    // Deploy a test contract
    var contractAddress = await DeployTestContract();
    
    // Attempt to set author to null
    var result = await ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.SetContractAuthor), 
        new SetContractAuthorInput
        {
            ContractAddress = contractAddress,
            NewAuthor = null  // This should be rejected but currently isn't
        });
    
    // Currently this succeeds (vulnerability)
    // After fix, this should fail with "Invalid input."
    result.Status.ShouldBe(TransactionResultStatus.Failed);
    result.Error.ShouldContain("Invalid input.");
    
    // Verify the author was NOT changed to null
    var author = await GetContractAuthor(contractAddress);
    author.ShouldNotBeNull();
}
```

## Notes

This vulnerability represents a critical gap in input validation that contradicts the defensive programming patterns established elsewhere in the codebase. The comparison with `SetSigner()` demonstrates that the development team is aware of null address risks, making this omission particularly significant. While the vulnerability requires author action to trigger, the permanent and irreversible nature of the consequences, combined with realistic accidental trigger scenarios (especially protobuf's default-null behavior), elevates this to a genuine security concern rather than mere operational guidance.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L175-183)
```csharp
    public override Hash ProposeUpdateContract(ContractUpdateInput input)
    {
        var proposedContractInputHash = CalculateHashFromInput(input);
        RegisterContractProposingData(proposedContractInputHash);

        var contractAddress = input.Address;
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        AssertAuthorityByContractInfo(info, Context.Sender);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L324-334)
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
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L445-452)
```csharp
    public override Empty UpdateUserSmartContract(UserContractUpdateInput input)
    {
        AssertInlineDeployOrUpdateUserContract();

        var info = State.ContractInfos[input.Address];
        Assert(info != null, "Contract not found.");
        Assert(Context.Sender == info.Author, "No permission.");
        Assert(info.Deployer == null || info.Deployer == Context.Sender, "No permission to update.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L519-535)
```csharp
    public override Empty SetContractAuthor(SetContractAuthorInput input)
    {
        var info = State.ContractInfos[input.ContractAddress];
        Assert(info != null, "Contract not found.");
        var oldAuthor = info.Author;
        Assert(Context.Sender == info.Author, "No permission.");
        info.Author = input.NewAuthor;
        State.ContractInfos[input.ContractAddress] = info;
        Context.Fire(new AuthorUpdated()
        {
            Address = input.ContractAddress,
            OldAuthor = oldAuthor,
            NewAuthor = input.NewAuthor
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L537-545)
```csharp
    public override Empty SetSigner(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input.");

        if (State.SignerMap[Context.Sender] == input) return new Empty();

        State.SignerMap[Context.Sender] = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L98-102)
```csharp
    private void UpdateSmartContract(Address contractAddress, byte[] code, Address author, bool isUserContract)
    {
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        Assert(author == info.Author, "No permission.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L241-244)
```csharp
    private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
    {
        Assert(contractInfo.Author == Context.Self || address == contractInfo.Author, "No permission.");
    }
```

**File:** protobuf/aelf/core.proto (L135-138)
```text
message Address
{
    bytes value = 1;
}
```

**File:** protobuf/acs0.proto (L310-313)
```text
message SetContractAuthorInput{
    aelf.Address contract_address = 1;
    aelf.Address new_author = 2;
}
```
