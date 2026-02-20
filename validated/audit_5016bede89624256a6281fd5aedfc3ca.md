# Audit Report

## Title
User Contract Authorization Bypass via isUserContract Flag Manipulation During Updates

## Summary
User contract authors can permanently bypass the stricter miner-based authorization model by updating their contracts through `ProposeUpdateContract` instead of `UpdateUserSmartContract`. This flips the `isUserContract` flag from `true` to `false`, allowing all future updates to bypass miner approval and use only Parliament governance.

## Finding Description

The Genesis contract (BasicContractZero) implements two distinct update paths with different authorization models:

**User Contract Path (Stricter):**
- Uses `UpdateUserSmartContract` → `ReleaseApprovedUserSmartContract` (requires current miner) → `PerformUpdateUserSmartContract`

**Regular Contract Path (Weaker):**
- Uses `ProposeUpdateContract` → `ReleaseCodeCheckedContract` (no miner check) → `UpdateSmartContract`

The vulnerability exists because `ProposeUpdateContract` does not validate whether the target contract is a user contract. When called on a user contract, it preserves only the `IsSystemContract` flag [1](#0-0)  but ignores `isUserContract`, routing to `UpdateSmartContract` as the release method [2](#0-1) .

The authorization check only validates that the sender is the contract author [3](#0-2) , with no check preventing user contracts from using this path.

When `UpdateSmartContract` executes, it hardcodes `isUserContract` to `false` [4](#0-3) . The private helper then unconditionally overwrites the contract info [5](#0-4) , permanently changing the contract from user to regular.

User contracts are designed to require miner authorization through `ReleaseApprovedUserSmartContract`, which enforces `AssertCurrentMiner()` [6](#0-5) . After the flag flip, subsequent updates use `ReleaseCodeCheckedContract`, which only validates proposer match [7](#0-6)  with no miner requirement.

The correct path through `PerformUpdateUserSmartContract` properly preserves the flag by passing `true` [8](#0-7) .

## Impact Explanation

This is a **High** severity governance vulnerability:

1. **Authorization Model Bypass**: User contracts were intentionally designed with stricter authorization requiring miner approval. This vulnerability allows authors to unilaterally downgrade to Parliament-only governance.

2. **Permanent State Corruption**: Once flipped to `false`, the contract permanently loses user contract status. All future updates bypass miner authorization.

3. **Protocol Invariant Violation**: Contract types should be immutable after deployment. Users deploying user contracts expect the stricter governance model to remain permanent.

4. **Trust Violation**: Stakeholders interacting with user contracts make decisions based on the governance model. Silent alteration betrays their security assumptions.

## Likelihood Explanation

**High Likelihood** - The attack is easily executable:

**Attacker Capabilities:**
- Must be author of a user contract (obtainable by deploying one via `DeployUserSmartContract`)
- Requires Parliament approval (same governance as legitimate updates)

**Attack Complexity:**
- **Low** - Simply call `ProposeUpdateContract` instead of `UpdateUserSmartContract`
- Both methods are public and accessible to contract authors
- No technical sophistication required

**Feasibility:**
1. Deploy user contract via standard mechanisms
2. Call `ProposeUpdateContract(userContractAddress, newCode)`
3. Obtain Parliament approval
4. Pass code check
5. Flag automatically flips during execution

## Recommendation

Add validation in `ProposeUpdateContract` to prevent user contracts from using this path:

```csharp
public override Hash ProposeUpdateContract(ContractUpdateInput input)
{
    // ... existing code ...
    var info = State.ContractInfos[contractAddress];
    Assert(info != null, "Contract not found.");
    Assert(!info.IsUserContract, "User contracts must use UpdateUserSmartContract method.");
    AssertAuthorityByContractInfo(info, Context.Sender);
    // ... rest of method ...
}
```

This ensures user contracts can only be updated through the correct path that preserves their authorization model.

## Proof of Concept

```csharp
[Fact]
public async Task UserContract_AuthorizationBypass_Via_ProposeUpdateContract()
{
    // 1. Deploy a user contract
    var userCode = Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value;
    var deployResult = await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.DeployUserSmartContract),
        new UserContractDeploymentInput {
            Category = KernelConstants.DefaultRunnerCategory,
            Code = ByteString.CopyFrom(userCode)
        });
    
    var contractAddress = ContractDeployed.Parser
        .ParseFrom(deployResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed)
        .Address;
    
    // Verify it's a user contract
    var info = await GetContractInfo(contractAddress);
    Assert.True(info.IsUserContract);
    
    // 2. Malicious update via ProposeUpdateContract (should fail but doesn't)
    var newCode = Codes.Single(kv => kv.Key.Contains("TokenHolder")).Value;
    var updateResult = await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ProposeUpdateContract),
        new ContractUpdateInput {
            Address = contractAddress,
            Code = ByteString.CopyFrom(newCode)
        });
    
    // This succeeds when it should fail
    Assert.Equal(TransactionResultStatus.Mined, updateResult.Status);
    
    // 3. After Parliament approval and code check, flag is flipped
    // ... approval flow ...
    
    // 4. Verify flag is now false
    var updatedInfo = await GetContractInfo(contractAddress);
    Assert.False(updatedInfo.IsUserContract); // Permanently corrupted!
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L514-514)
```csharp
        UpdateSmartContract(input.Address, input.Code.ToByteArray(), proposingInput.Author, true);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L110-110)
```csharp
        info.IsUserContract = isUserContract;
```
