# Audit Report

## Title
Authorization Bypass in Contract Update Proposals for Non-Whitelisted Deployers

## Summary
A logic error in `AssertAuthorityByContractInfo` allows anyone to propose updates to contracts deployed by non-whitelisted users. The vulnerability stems from checking whether the contract's AUTHOR is Contract Zero instead of checking whether the SENDER has appropriate authority, breaking the fundamental security guarantee that only deployers control their contracts.

## Finding Description

The vulnerability exists in the authorization logic for contract update proposals. When a non-whitelisted user deploys a contract, the `DecideNonSystemContractAuthor` function assigns `Context.Self` (Contract Zero's address) as the contract author instead of the deployer's address. [1](#0-0) 

This author assignment is used during contract deployment when `DeploySmartContract` is called. [2](#0-1) 

The critical flaw occurs in the update authorization check. When anyone attempts to propose a contract update via `ProposeUpdateContract`, the system validates their authority using `AssertAuthorityByContractInfo`. [3](#0-2) 

The `AssertAuthorityByContractInfo` function contains the flawed logic with the condition `contractInfo.Author == Context.Self || address == contractInfo.Author`. This checks if the contract's AUTHOR is Contract Zero, not whether the SENDER is authorized. [4](#0-3) 

When the author IS Contract Zero (which happens for all non-whitelisted deployments), the first condition evaluates to TRUE regardless of who is proposing the update, allowing anyone to bypass authorization.

**Attack Flow**:
1. Non-whitelisted user deploys contract → author set to Context.Self
2. Any attacker calls `ProposeUpdateContract` on that contract
3. Authorization check passes because `contractInfo.Author == Context.Self` is TRUE
4. Attacker can propose malicious updates (still requires governance approval)

**Root Cause Analysis**: The Parliament contract uses a global whitelist for validation rather than per-organization whitelists. [5](#0-4)  On main chain, this whitelist is typically empty, causing ALL non-system contracts deployed through Parliament to have `Context.Self` as their author, making them vulnerable.

Test evidence confirms this behavior. Contracts deployed on main chain with Parliament governance have BasicContractZeroAddress as author. [6](#0-5)  In contrast, contracts deployed with Association-based controllers where the proposer is whitelisted retain the actual proposer as author. [7](#0-6) 

## Impact Explanation

**Authorization Model Broken**: Non-whitelisted deployers lose exclusive control over their contracts. While whitelisted deployers retain authorship and can exclusively propose updates, non-whitelisted deployers have their contracts "owned" by Contract Zero, allowing anyone to propose updates.

**Increased Attack Surface**: The number of users who can propose malicious updates increases from 1 (the legitimate deployer) to all users on the chain. This dramatically increases the attack surface for social engineering attacks against governance.

**Governance Overhead**: The governance system must review proposals from arbitrary users instead of just trusted contract authors, increasing workload and potential for mistakes.

**Asymmetric Security Model**: Creates an unfair two-tier system where whitelisted users have security guarantees that non-whitelisted users do not, even though both pay for deployment through governance proposals.

This is classified as **Medium severity** because:
- Authorization bypass is complete for the proposal stage
- Governance approval still required for execution (defense-in-depth mitigation)
- Real-world impact on main chain and shared side chains where non-whitelisted deployment occurs
- Breaks fundamental security guarantee of deployer control

## Likelihood Explanation

**High Likelihood** because:

**Attacker Capabilities**: Any user with a standard account can exploit this. No special permissions, resources, or technical sophistication required. Simply calling `ProposeUpdateContract` with a target contract address is sufficient.

**Preconditions**: 
- Contract deployed by non-whitelisted user (common on main chain with Parliament controller)
- `ContractDeploymentAuthorityRequired` is true (standard production setting)
- Attacker knows address of target contract

**Attack Complexity**: Low
1. Identify any contract deployed through Parliament governance on main chain
2. Call `ProposeUpdateContract` with malicious code
3. Use social engineering to convince governance to approve

**Real-World Scenarios**: On main chain, the Parliament whitelist is typically empty, meaning ALL non-system contracts are vulnerable. Shared side chains explicitly designed to allow "anyone to propose contracts" are directly affected.

## Recommendation

The fix requires changing the authorization logic to check if the SENDER is authorized, not if the contract's AUTHOR is Context.Self:

```csharp
private void AssertAuthorityByContractInfo(ContractInfo contractInfo, Address address)
{
    Assert(Context.Sender == Context.Self || address == contractInfo.Author, "No permission.");
}
```

This would ensure that:
- Only Contract Zero itself (for system updates) can propose updates to contracts owned by Context.Self
- Only the actual author can propose updates to contracts they deployed

Alternatively, ensure that non-system contracts always have a real author (not Context.Self) by modifying `DecideNonSystemContractAuthor` to return the actual proposer or sender even when not in the whitelist, and handle authorization through different means.

## Proof of Concept

```csharp
[Fact]
public async Task AuthorizationBypass_NonWhitelistedContract_AnyoneCanProposeUpdate()
{
    // Deploy contract through Parliament (proposer not in whitelist)
    var contractDeploymentInput = new ContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("MultiToken")).Value)
    };

    // Go through full deployment flow (propose, approve, release)
    var proposingTxResult = await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(BasicContractZero.ProposeNewContract), 
        contractDeploymentInput);
    
    var proposedHash = ContractProposed.Parser.ParseFrom(
        proposingTxResult.Logs.First(l => l.Name.Contains(nameof(ContractProposed))).NonIndexed
    ).ProposedContractInputHash;
    
    var proposalId = ProposalCreated.Parser.ParseFrom(
        proposingTxResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed
    ).ProposalId;

    await ApproveWithMinersAsync(Tester, ParliamentAddress, proposalId);
    var releaseResult = await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(BasicContractZero.ReleaseApprovedContract),
        new ReleaseContractInput { ProposalId = proposalId, ProposedContractInputHash = proposedHash });

    var codeCheckProposalId = ProposalCreated.Parser.ParseFrom(
        releaseResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed
    ).ProposalId;
    
    await ApproveWithMinersAsync(Tester, ParliamentAddress, codeCheckProposalId);
    var deployResult = await Tester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(BasicContractZero.ReleaseCodeCheckedContract),
        new ReleaseContractInput { ProposedContractInputHash = proposedHash, ProposalId = codeCheckProposalId });

    var deployedAddress = ContractDeployed.Parser.ParseFrom(
        deployResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed
    ).Address;
    
    // Verify author is BasicContractZeroAddress (vulnerable state)
    var author = Address.Parser.ParseFrom(await Tester.CallContractMethodAsync(
        BasicContractZeroAddress,
        nameof(BasicContractZero.GetContractAuthor), 
        deployedAddress));
    author.ShouldBe(BasicContractZeroAddress);

    // Attacker (different user) proposes update
    var attackerTester = Tester.CreateNewContractTester(SampleECKeyPairs.KeyPairs[1]);
    var attackResult = await attackerTester.ExecuteContractWithMiningAsync(
        BasicContractZeroAddress,
        nameof(BasicContractZero.ProposeUpdateContract), 
        new ContractUpdateInput
        {
            Address = deployedAddress,
            Code = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value)
        });

    // VULNERABILITY: Should fail with "No permission" but succeeds!
    attackResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var updateHash = ContractProposed.Parser.ParseFrom(
        attackResult.Logs.First(l => l.Name.Contains(nameof(ContractProposed))).NonIndexed
    ).ProposedContractInputHash;
    updateHash.ShouldNotBeNull(); // Attacker successfully bypassed authorization
}
```

**Notes**: This vulnerability affects all contracts deployed through Parliament governance on the main chain where the proposer whitelist is empty. The Association contract behaves differently by checking per-organization whitelists, making it less vulnerable in scenarios where specific proposers are whitelisted within the organization.

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L317-321)
```csharp
        var address =
            DeploySmartContract(null, input.Category, input.Code.ToByteArray(), false,
                DecideNonSystemContractAuthor(contractProposingInput?.Proposer, Context.Sender), false,
                input.ContractOperation?.Deployer, input.ContractOperation?.Salt);
        return address;
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L268-271)
```csharp
    public override BoolValue ValidateProposerInWhiteList(ValidateProposerInWhiteListInput input)
    {
        return new BoolValue { Value = ValidateAddressInWhiteList(input.Proposer) };
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
