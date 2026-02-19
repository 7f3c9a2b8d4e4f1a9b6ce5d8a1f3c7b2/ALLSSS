# Audit Report

## Title
User Contract Authorization Bypass via isUserContract Flag Manipulation During Updates

## Summary
Contract authors can bypass the stricter miner-based authorization model for user contracts by updating them through `ProposeUpdateContract` instead of `UpdateUserSmartContract`. This permanently flips the `isUserContract` flag from `true` to `false`, allowing future updates to bypass the `AssertCurrentMiner()` requirement and use Parliament governance instead.

## Finding Description

User contracts in AElf are designed with a stricter authorization model requiring miner approval for updates. However, a critical flaw in the contract update flow allows authors to bypass this protection.

When a contract author calls `ProposeUpdateContract` on a user contract, the method only validates author permission but does not enforce that user contracts must use the dedicated `UpdateUserSmartContract` path. [1](#0-0) 

The proposal creation at line 215 preserves the `IsSystemContract` flag but completely omits preservation of the `isUserContract` flag. [2](#0-1)  The method routes to `UpdateSmartContract` for execution. [3](#0-2) 

When `UpdateSmartContract` executes, it hardcodes the `isUserContract` parameter to `false` regardless of the original contract type. [4](#0-3) 

The private helper method then unconditionally overwrites the contract's `IsUserContract` flag with the provided value. [5](#0-4) 

This breaks the security guarantee that user contracts require miner authorization. User contract updates should go through `ReleaseApprovedUserSmartContract`, which enforces `AssertCurrentMiner()`. [6](#0-5) 

Once the flag is flipped, subsequent updates use `ReleaseCodeCheckedContract`, which only validates the proposer identity without requiring miner approval. [7](#0-6) 

## Impact Explanation

This vulnerability has **High** severity impact because it:

1. **Permanently alters authorization requirements**: Once exploited, the contract permanently loses its miner-based protection, fundamentally changing its security model
2. **Violates protocol invariants**: Contract types (system/user/regular) should be immutable once deployed, but this allows mutation
3. **Affects governance integrity**: Users and stakeholders who deployed contracts expecting miner oversight lose that protection
4. **No reversion mechanism**: There is no legitimate way to restore the `isUserContract` flag once changed

The attack allows contract authors to unilaterally downgrade their contract's security guarantees from requiring current miner approval to only requiring Parliament governance approval.

## Likelihood Explanation

The likelihood is **High** because:

1. **Low attack complexity**: The attacker simply calls `ProposeUpdateContract` instead of `UpdateUserSmartContract` - both are public methods
2. **Minimal prerequisites**: The attacker only needs to be the contract author (obtainable by deploying a user contract) and obtain standard Parliament approval
3. **No detection mechanisms**: The flag change happens silently in state without emitting distinguishing events
4. **Standard governance process**: The approval requirements are identical to legitimate contract updates, making malicious updates indistinguishable

Any motivated contract author can execute this attack with only the cost of obtaining Parliament approval, which is the standard governance process for contract updates.

## Recommendation

Add validation in `ProposeUpdateContract` to prevent user contracts from using this path:

```csharp
public override Hash ProposeUpdateContract(ContractUpdateInput input)
{
    var proposedContractInputHash = CalculateHashFromInput(input);
    RegisterContractProposingData(proposedContractInputHash);

    var contractAddress = input.Address;
    var info = State.ContractInfos[contractAddress];
    Assert(info != null, "Contract not found.");
    
    // ADD THIS CHECK:
    Assert(!info.IsUserContract, "User contracts must use UpdateUserSmartContract.");
    
    AssertAuthorityByContractInfo(info, Context.Sender);
    // ... rest of method
}
```

Alternatively, preserve the `isUserContract` flag in the proposal:

```csharp
Params = new ContractCodeCheckInput
{
    ContractInput = input.ToByteString(),
    CodeCheckReleaseMethod = nameof(UpdateSmartContract),
    ProposedContractInputHash = proposedContractInputHash,
    Category = info.Category,
    IsSystemContract = info.IsSystemContract,
    IsUserContract = info.IsUserContract  // ADD THIS LINE
}.ToByteString(),
```

And modify `UpdateSmartContract` to accept and preserve the flag value instead of hardcoding it.

## Proof of Concept

```csharp
[Fact]
public async Task UserContract_AuthorizationBypass_Via_ProposeUpdateContract()
{
    // Step 1: Deploy a user contract
    var userContractCode = Codes.Single(kv => kv.Key.Contains("TokenHolder")).Value;
    var deployInput = new UserContractDeploymentInput
    {
        Category = 0,
        Code = ByteString.CopyFrom(userContractCode)
    };
    
    var deployResult = await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.DeployUserSmartContract), 
        deployInput);
    
    // Get deployed contract address and verify it's a user contract
    var contractAddress = /* extract from events */;
    var info = await GetContractInfo(contractAddress);
    Assert.True(info.IsUserContract); // Initial state
    
    // Step 2: Update via ProposeUpdateContract (wrong path)
    var updateInput = new ContractUpdateInput
    {
        Address = contractAddress,
        Code = ByteString.CopyFrom(updatedCode)
    };
    
    await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ProposeUpdateContract),
        updateInput);
    
    // Step 3: Get Parliament approval and release
    // ... approval and release steps ...
    
    // Step 4: Verify flag is now false
    var updatedInfo = await GetContractInfo(contractAddress);
    Assert.False(updatedInfo.IsUserContract); // Flag flipped!
    
    // Step 5: Future updates no longer require miner approval
    // They can now go through ReleaseCodeCheckedContract instead of
    // ReleaseApprovedUserSmartContract (which requires AssertCurrentMiner)
}
```

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L183-183)
```csharp
        AssertAuthorityByContractInfo(info, Context.Sender);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L212-212)
```csharp
                    CodeCheckReleaseMethod = nameof(UpdateSmartContract),
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L215-215)
```csharp
                    IsSystemContract = info.IsSystemContract
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L299-299)
```csharp
            contractProposingInput.Proposer == Context.Sender, "Invalid contract proposing status.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L334-334)
```csharp
        UpdateSmartContract(contractAddress, input.Code.ToByteArray(), info.Author, false);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L485-485)
```csharp
        AssertCurrentMiner();
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L110-110)
```csharp
        info.IsUserContract = isUserContract;
```
