# Audit Report

## Title
Authorization Bypass in Contract Update Proposals for Non-Whitelisted Deployers

## Summary
A logic error in `AssertAuthorityByContractInfo` allows anyone to propose updates to contracts deployed by non-whitelisted users. When non-whitelisted users deploy contracts, the author is set to Contract Zero's address (`Context.Self`), and the flawed authorization check passes for any sender when the contract author equals `Context.Self`, bypassing the intended restriction that only contract authors can propose updates.

## Finding Description

The vulnerability exists in the contract update authorization logic within the Genesis contract. The complete attack path is:

**Author Assignment During Deployment**: When a non-whitelisted user deploys a contract through the governance proposal process, the `DecideNonSystemContractAuthor` function assigns `Context.Self` (Contract Zero's address) as the contract author instead of the deployer's address: [1](#0-0) 

This author value is then stored in the contract's metadata during deployment: [2](#0-1) 

**Flawed Authorization Check**: When anyone attempts to propose a contract update via `ProposeUpdateContract`, the system validates their authority using `AssertAuthorityByContractInfo`: [3](#0-2) 

The `AssertAuthorityByContractInfo` function contains the critical flaw: [4](#0-3) 

The condition `contractInfo.Author == Context.Self || address == contractInfo.Author` checks if the contract's **author** is Contract Zero, not whether the **sender** has appropriate authority. When the author IS Contract Zero (which happens for all non-whitelisted deployments), the first condition evaluates to TRUE regardless of who is proposing the update.

**Attack Execution**:
1. Non-whitelisted user deploys contract → author automatically set to `Context.Self`
2. Any attacker identifies the contract address
3. Attacker calls `ProposeUpdateContract` with malicious code
4. Authorization check passes because `contractInfo.Author == Context.Self` is TRUE
5. Attacker successfully creates a governance proposal (though it still requires approval)

**Test Evidence**: Existing tests confirm the author assignment behavior:
- Contracts deployed through standard governance process have BasicContractZeroAddress as author: [5](#0-4) 
- Whitelisted deployments retain the proposer as author: [6](#0-5) 

Critically, no tests verify whether a different user can propose updates to contracts with BasicContractZeroAddress as author, which would have revealed this vulnerability.

## Impact Explanation

**Broken Authorization Model**: Non-whitelisted deployers lose exclusive control over proposing updates to their contracts. While whitelisted deployers retain authorship and can exclusively propose updates, non-whitelisted deployers have their contracts effectively "owned" by Contract Zero, allowing any user to propose updates.

**Increased Attack Surface**: The number of users who can propose malicious updates increases from 1 (the legitimate deployer) to all users on the chain. This dramatically increases the attack surface for social engineering attacks against governance organizations.

**Governance Overhead**: The governance system must review proposals from arbitrary users instead of just trusted contract authors, increasing workload and the potential for approval mistakes under proposal fatigue.

**Asymmetric Security Model**: Creates an unfair two-tier system where whitelisted users have security guarantees that non-whitelisted users do not, even though both paths require governance approval for deployment.

**Severity Justification (Medium)**: While the authorization bypass is complete for the proposal stage, governance approval is still required for execution, providing defense-in-depth mitigation. However, the fundamental security guarantee that deployers control their contract updates is broken, and the increased attack surface for social engineering represents real risk on production chains, especially side chains where non-whitelisted deployment is explicitly intended.

## Likelihood Explanation

**High Likelihood** due to:

**Attacker Capabilities**: Any user with a standard account can exploit this vulnerability. No special permissions, resources, or technical sophistication required beyond basic contract interaction.

**Preconditions Are Common**: 
- Contracts deployed by non-whitelisted users (explicitly common on shared side chains)
- `ContractDeploymentAuthorityRequired` set to true (standard production configuration)
- Attacker knows the contract address (publicly available on-chain information)

**Low Attack Complexity**: The exploit requires only:
1. Identify a contract deployed by a non-whitelisted user
2. Call `ProposeUpdateContract` with desired code
3. (Optional) Attempt social engineering to convince governance to approve

**Real-World Impact**: Shared side chains are explicitly designed to allow "anyone to propose contracts" through governance. All such contracts are vulnerable to this authorization bypass, making the issue immediately exploitable on production deployments.

## Recommendation

Fix the `AssertAuthorityByContractInfo` logic to properly validate sender authority instead of checking if the contract author is Contract Zero:

```csharp
private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
{
    // Only allow the actual contract author to propose updates, or Contract Zero itself
    Assert(address == contractInfo.Author || (address == Context.Self && contractInfo.Author == Context.Self), 
           "No permission.");
}
```

Alternatively, modify `DecideNonSystemContractAuthor` to assign the actual proposer as author even for non-whitelisted deployments, maintaining a separate governance approval requirement without compromising the deployer's exclusive proposal rights.

## Proof of Concept

```csharp
[Fact]
public async Task AuthorizationBypass_AnyoneCanProposeUpdateForNonWhitelistedContract()
{
    // Deploy contract through standard governance process (non-whitelisted)
    var contractCode = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value);
    var deploymentInput = new ContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = contractCode
    };
    
    var deployedAddress = await DeployAsync(Tester, ParliamentAddress, BasicContractZeroAddress, deploymentInput);
    
    // Verify contract author is BasicContractZeroAddress (not the deployer)
    var contractInfo = ContractInfo.Parser.ParseFrom(
        await Tester.CallContractMethodAsync(BasicContractZeroAddress,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.GetContractInfo), 
            deployedAddress));
    contractInfo.Author.ShouldBe(BasicContractZeroAddress);
    
    // Create attacker using completely different keypair
    var attackerTester = Tester.CreateNewContractTester(AnotherUserKeyPair);
    
    // Attacker proposes malicious update to victim's contract
    var maliciousCode = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("TestContract.BasicFunction")).Value);
    var updateInput = new ContractUpdateInput
    {
        Address = deployedAddress,
        Code = maliciousCode
    };
    
    // VULNERABILITY: This should fail with "No permission" but succeeds
    var attackResult = await attackerTester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(BasicContractZero.ProposeUpdateContract), 
        updateInput);
    
    attackResult.Status.ShouldBe(TransactionResultStatus.Mined); // Proves authorization bypass
    
    var proposalId = ProposalCreated.Parser
        .ParseFrom(attackResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;
    proposalId.ShouldNotBeNull(); // Attacker successfully created proposal
}
```

### Citations

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L180-184)
```csharp
        var contractAddress = input.Address;
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        AssertAuthorityByContractInfo(info, Context.Sender);
        AssertContractVersion(info.ContractVersion, input.Code, info.Category);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L317-321)
```csharp
        var address =
            DeploySmartContract(null, input.Category, input.Code.ToByteArray(), false,
                DecideNonSystemContractAuthor(contractProposingInput?.Proposer, Context.Sender), false,
                input.ContractOperation?.Deployer, input.ContractOperation?.Salt);
        return address;
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L248-258)
```csharp
        var creator = ContractDeployed.Parser.ParseFrom(deploymentResult.Logs[1].Indexed[0]).Author;
        creator.ShouldBe(BasicContractZeroAddress);
        var deployAddress = ContractDeployed.Parser.ParseFrom(deploymentResult.Logs[1].NonIndexed).Address;
        deployAddress.ShouldNotBeNull();

        var contractVersion = ContractDeployed.Parser.ParseFrom(deploymentResult.Logs[1].NonIndexed).Version;
        contractVersion.ShouldBe(1);
        var contractInfo = ContractInfo.Parser.ParseFrom(await Tester.CallContractMethodAsync(BasicContractZeroAddress,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.GetContractInfo), deployAddress));
        contractInfo.Version.ShouldBe(1);
        contractInfo.Author.ShouldBe(BasicContractZeroAddress);
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L928-940)
```csharp
        var creator = ContractDeployed.Parser
            .ParseFrom(deploymentResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).Indexed[0])
            .Author;

        creator.ShouldBe(AnotherMinerAddress);

        var deployAddress = ContractDeployed.Parser
            .ParseFrom(deploymentResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed)
            .Address;
        var author = Address.Parser.ParseFrom(await Tester.CallContractMethodAsync(BasicContractZeroAddress,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.GetContractAuthor), deployAddress));

        author.ShouldBe(AnotherMinerAddress);
```
