# Audit Report

## Title
Contract Ownership Theft via Expired Proposal State Overwrite

## Summary
The `SendUserContractProposal()` function in the Genesis contract allows attackers to overwrite expired proposal metadata while an approved governance proposal is still pending execution. By submitting identical contract deployment inputs after the expiration period, an attacker can replace the legitimate author's address with their own, resulting in complete ownership theft when miners release the original approved proposal.

## Finding Description

The vulnerability exists in the user contract deployment workflow within the Genesis (BasicContractZero) contract. The core issue is a race condition between proposal expiration and governance execution that allows state overwriting.

**Vulnerable Code Flow:**

The `SendUserContractProposal()` helper method contains a critical flaw in its expiration check that explicitly permits overwriting the state mapping when the expiration time has passed, without verifying whether an approved governance proposal for that input hash is still pending execution. [1](#0-0) 

When this condition evaluates to true (after expiration), the function proceeds to completely overwrite the `ContractProposingInputMap` state entry with a new `ContractProposingInput` structure, critically setting `Author = Context.Sender` which replaces the legitimate user's address with the attacker's address. [2](#0-1) 

The state mapping is keyed solely by the input hash, not by proposal ID, allowing multiple governance proposals with different IDs to reference the same state entry. [3](#0-2) 

**Attack Execution Path:**

1. A legitimate user calls `DeployUserSmartContract()` which invokes `SendUserContractProposal()` to create a state entry with `Author = UserAddress` and initiates a governance proposal P1. [4](#0-3) 

2. The default code check proposal expiration period is 900 seconds (15 minutes). [5](#0-4) 

3. After governance approval but before release, if the current block time exceeds the expiration time, an attacker submits identical deployment inputs, generating the same input hash. The state is completely overwritten with `Author = AttackerAddress`.

4. When a miner releases the **original approved proposal P1** via `ReleaseApprovedUserSmartContract()`, it retrieves the state entry by input hash which now contains the attacker's address. The validation checks pass because both the legitimate and attacker proposals set `Proposer = Context.Self` (the Genesis contract address), not the user's address. [6](#0-5) 

5. When the code check controller calls back to `PerformDeployUserSmartContract()`, it retrieves the compromised state entry and deploys the contract using `contractProposingInput.Author` as both the author and deployer parameters, which is now the attacker's address. [7](#0-6) 

**Why Existing Protections Fail:**

The `ReleaseApprovedUserSmartContract()` validation cannot distinguish between the legitimate user's state and the attacker's overwrite because the proposer check verifies `Context.Self`, and there is no validation linking the proposal ID being released to the state entry's creation timestamp or original author.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables complete contract ownership theft with the following concrete impacts:

1. **Unauthorized Contract Control**: The attacker gains full authorship rights to the deployed contract. The `UpdateUserSmartContract()` method validates `Context.Sender == info.Author` before allowing updates, permanently locking out the legitimate user. [8](#0-7) 

2. **Authorship Transfer**: The attacker can transfer stolen ownership via `SetContractAuthor()` to other addresses, making the theft permanent. [9](#0-8) 

3. **Governance Integrity Violation**: This breaks a fundamental invariant—approved governance proposals must execute with the parameters that were approved. Miners approved deployment with `Author = LegitimateUser`, but the contract deploys with `Author = Attacker`, undermining trust in the entire governance system.

4. **Financial Loss**: The legitimate user loses both the deployed contract and all associated value/fees paid for deployment.

The same vulnerability affects `UpdateUserSmartContract()`, allowing attackers to steal update rights for existing contracts. [10](#0-9) 

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack is highly feasible under realistic conditions:

**Attacker Capabilities:**
- On main chains and public sidechains, any user can call `DeployUserSmartContract()` without special permissions. The access check only restricts deployment on private sidechains where the sender must be in the Parliament whitelist. [11](#0-10) 

- The attacker can monitor `CodeCheckRequired` events to detect when contracts are proposed and compute identical input hashes since contract code is public.

**Preconditions:**
- The critical precondition is that the time between proposal approval and release exceeds the `CodeCheckProposalExpirationTimePeriod` (default 15 minutes). This occurs realistically during network congestion, off-peak hours when miner activity is reduced, or operational delays in automated proposal release systems.

**Attack Complexity: LOW**
1. Monitor for `CodeCheckRequired` events from contract deployments
2. Query the expiration time period
3. Wait until current time exceeds expiration
4. Submit identical deployment input
5. Wait for miners to release the original approved proposal

**Detection Difficulty**: The attack produces normal-looking on-chain behavior with standard events, making it difficult to detect without correlating governance proposal IDs with state changes.

## Recommendation

Implement one or more of the following fixes:

1. **Link Proposal ID to State**: Store the proposal ID in the `ContractProposingInput` structure and validate it matches during release:

```csharp
// In ContractProposingInput structure, add:
public Hash ProposalId { get; set; }

// In SendUserContractProposal, store the proposal ID after creation

// In ReleaseApprovedUserSmartContract, add validation:
Assert(contractProposingInput.ProposalId == input.ProposalId, 
    "Proposal ID mismatch with stored state.");
```

2. **Prevent Overwrite of Approved Proposals**: Modify the expiration check to prevent overwriting if status indicates governance approval:

```csharp
Assert(registered == null || 
       (Context.CurrentBlockTime >= registered.ExpiredTime && 
        registered.Status == ContractProposingInputStatus.Proposed), 
       "Already proposed or approved.");
```

3. **Store Original Author**: Add a separate field for the original proposer that cannot be overwritten:

```csharp
public Address OriginalAuthor { get; set; }
// Set once during initial proposal and never allow modification
```

## Proof of Concept

```csharp
[Fact]
public async Task ContractOwnershipTheft_Via_ExpiredProposalOverwrite_Test()
{
    // 1. Legitimate user deploys contract
    var legitimateUser = SampleAddress.AddressList[0];
    var contractCode = Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value;
    
    var deployInput = new UserContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = ByteString.CopyFrom(contractCode),
        Salt = HashHelper.ComputeFrom("unique_salt")
    };
    
    var deployResult = await ExecuteAsUser(legitimateUser, 
        nameof(BasicContractZero.DeployUserSmartContract), deployInput);
    deployResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var proposalId = ExtractProposalId(deployResult);
    var inputHash = HashHelper.ComputeFrom(deployInput);
    
    // 2. Miners approve the proposal
    await ApproveWithMinersAsync(ParliamentAddress, proposalId);
    
    // 3. Wait for expiration (advance block time past 900 seconds)
    await AdvanceBlockTime(901);
    
    // 4. Attacker overwrites state with identical input
    var attacker = SampleAddress.AddressList[1];
    var attackResult = await ExecuteAsUser(attacker, 
        nameof(BasicContractZero.DeployUserSmartContract), deployInput);
    attackResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // 5. Miner releases original approved proposal
    var releaseResult = await ExecuteAsMiner(
        nameof(BasicContractZero.ReleaseApprovedUserSmartContract),
        new ReleaseContractInput { ProposalId = proposalId, ProposedContractInputHash = inputHash });
    releaseResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // 6. Verify contract deployed with ATTACKER as author (ownership theft)
    var contractAddress = ExtractContractAddress(releaseResult);
    var authorInfo = await GetContractAuthor(contractAddress);
    
    authorInfo.ShouldBe(attacker); // VULNERABILITY: Should be legitimateUser!
    authorInfo.ShouldNotBe(legitimateUser); // Legitimate user lost ownership
}
```

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L314-315)
```csharp
        var registered = State.ContractProposingInputMap[proposingInputHash];
        Assert(registered == null || Context.CurrentBlockTime >= registered.ExpiredTime, "Already proposed.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L316-323)
```csharp
        var proposedInfo = new ContractProposingInput
        {
            Proposer = Context.Self,
            Status = ContractProposingInputStatus.CodeCheckProposed,
            ExpiredTime = Context.CurrentBlockTime.AddSeconds(GetCodeCheckProposalExpirationTimePeriod()),
            Author = Context.Sender
        };
        State.ContractProposingInputMap[proposingInputHash] = proposedInfo;
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L344-357)
```csharp
    private void AssertUserDeployContract()
    {
        // Only the symbol of main chain or public side chain is native symbol.
        RequireTokenContractContractAddressSet();
        var primaryTokenSymbol = State.TokenContract.GetPrimaryTokenSymbol.Call(new Empty()).Value;
        if (Context.Variables.NativeSymbol == primaryTokenSymbol)
        {
            return;
        }

        RequireParliamentContractAddressSet();
        var whitelist = State.ParliamentContract.GetProposerWhiteList.Call(new Empty());
        Assert(whitelist.Proposers.Contains(Context.Sender), "No permission.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroState.cs (L17-17)
```csharp
    public MappedState<Hash, ContractProposingInput> ContractProposingInputMap { get; set; }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L409-427)
```csharp
    public override DeployUserSmartContractOutput DeployUserSmartContract(UserContractDeploymentInput input)
    {
        AssertInlineDeployOrUpdateUserContract();
        AssertUserDeployContract();

        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        Context.LogDebug(() => "BasicContractZero - Deployment user contract hash: " + codeHash.ToHex());

        AssertContractNotExists(codeHash);

        if (input.Salt != null)
        {
            AssertContractAddressAvailable(Context.Sender, input.Salt);
        }

        var proposedContractInputHash = CalculateHashFromInput(input);
        SendUserContractProposal(proposedContractInputHash,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.PerformDeployUserSmartContract),
            input.ToByteString());
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L445-474)
```csharp
    public override Empty UpdateUserSmartContract(UserContractUpdateInput input)
    {
        AssertInlineDeployOrUpdateUserContract();

        var info = State.ContractInfos[input.Address];
        Assert(info != null, "Contract not found.");
        Assert(Context.Sender == info.Author, "No permission.");
        Assert(info.Deployer == null || info.Deployer == Context.Sender, "No permission to update.");
        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        Assert(info.CodeHash != codeHash, "Code is not changed.");
        AssertContractNotExists(codeHash);
        AssertContractVersion(info.ContractVersion, input.Code, info.Category);

        var proposedContractInputHash = CalculateHashFromInput(input);
        SendUserContractProposal(proposedContractInputHash,
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.PerformUpdateUserSmartContract),
            input.ToByteString());

        // Fire event to trigger BPs checking contract code
        Context.Fire(new CodeCheckRequired
        {
            Code = input.Code,
            ProposedContractInputHash = proposedContractInputHash,
            Category = info.Category,
            IsSystemContract = false,
            IsUserContract = true
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L476-483)
```csharp
    public override Empty ReleaseApprovedUserSmartContract(ReleaseContractInput input)
    {
        var contractProposingInput = State.ContractProposingInputMap[input.ProposedContractInputHash];

        Assert(
            contractProposingInput != null &&
            contractProposingInput.Status == ContractProposingInputStatus.CodeCheckProposed &&
            contractProposingInput.Proposer == Context.Self, "Invalid contract proposing status.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L495-504)
```csharp
    public override Address PerformDeployUserSmartContract(UserContractDeploymentInput input)
    {
        RequireSenderAuthority(State.CodeCheckController.Value.OwnerAddress);

        var inputHash = CalculateHashFromInput(input);
        TryClearContractProposingData(inputHash, out var contractProposingInput);

        var address = DeploySmartContract(null, input.Category, input.Code.ToByteArray(), false,
            contractProposingInput.Author, true, contractProposingInput.Author, input.Salt);
        return address;
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L6-6)
```csharp
    public const int DefaultCodeCheckProposalExpirationTimePeriod = 900; // 60 * 15
```
