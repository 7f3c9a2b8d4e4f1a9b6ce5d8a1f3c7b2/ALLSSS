# Audit Report

## Title
Code Hash Collision Enables Permanent Blocking of Legitimate Contract Deployments

## Summary
The `ProposeNewContract` function fails to prevent multiple simultaneous proposals with identical contract code but different parameters (e.g., category). This allows an attacker to front-run legitimate deployments, permanently blocking the victim's approved proposal and stealing contract authorship rights.

## Finding Description

The vulnerability exists in the contract proposal tracking mechanism. The system validates code hash uniqueness only against already-deployed contracts, not against pending proposals with the same code hash.

When `ProposeNewContract` is invoked, it computes the code hash and verifies it doesn't exist in already-deployed contracts [1](#0-0) . The validation uses `AssertContractNotExists`, which only checks `State.SmartContractRegistrations` [2](#0-1) .

However, proposals are tracked by `proposedContractInputHash`, calculated from the entire `ContractDeploymentInput` structure [3](#0-2) . This hash computation includes all input fields [4](#0-3) , including the category field which is user-specified [5](#0-4) .

The proposal registration only checks for duplicate `proposedContractInputHash` values [6](#0-5) , allowing multiple proposals with the same code but different parameters to coexist.

Code hashes are only registered in `State.SmartContractRegistrations` upon actual deployment [7](#0-6) . When the first proposal deploys successfully, the second deployment attempt with identical code will fail the duplicate code check [8](#0-7) .

The state structure confirms no separate tracking exists for code hashes of pending proposals [9](#0-8) .

## Impact Explanation

**HIGH Severity** - This vulnerability enables three critical impacts:

1. **Permanent Deployment Blocking**: The victim's approved proposal becomes permanently undeployable. Despite passing all governance and code check stages, deployment fails with "contract code has already been deployed before."

2. **Loss of Contract Authorship**: The attacker gains authorship rights to the deployed contract. Authorship controls all contract updates [10](#0-9)  and authorship transfers [11](#0-10) .

3. **Strategic Exploitation**: Attackers can block competitors from deploying critical infrastructure contracts or steal valuable deterministic contract addresses, causing protocol-level disruption.

## Likelihood Explanation

**MEDIUM Likelihood** - The attack requires:

1. **Monitoring proposals**: Trivial - all proposals are public on-chain data
2. **Submitting proposals**: Unrestricted - access control is disabled [12](#0-11) 
3. **Governance approval**: Requires coordination but achievable

While governance is assumed honest, the vulnerability exists in the contract logic itself. Honest governance may approve both proposals if they process proposals in batches without cross-checking code hashes, or if different category values appear to represent legitimately different deployment intents. The multi-stage governance process (Parliament approval → code check → deployment) provides a window of hours to days for the attack.

## Recommendation

Add code hash tracking for pending proposals. Modify `ProposeNewContract` to prevent new proposals if a pending proposal with the same code hash already exists:

```csharp
// After line 126 in BasicContractZero.cs, add:
AssertNoPendingProposalWithCodeHash(codeHash);
```

Implement the validation helper:

```csharp
private void AssertNoPendingProposalWithCodeHash(Hash codeHash)
{
    // Track code hashes of pending proposals in a new state mapping
    Assert(State.PendingCodeHashes[codeHash] == null, 
        "A proposal with this code hash is already pending.");
    State.PendingCodeHashes[codeHash] = true;
}
```

Clear the pending code hash tracking when proposals are deployed or expired.

## Proof of Concept

```csharp
[Fact]
public async Task CodeHashCollision_BlocksLegitimateDeployment()
{
    // Victim proposes contract with code X, category 1
    var victimProposal = await DeployAsync(code: SampleCode, category: 1);
    
    // Attacker proposes same code X, category 2 (different proposedContractInputHash)
    var attackerProposal = await DeployAsync(code: SampleCode, category: 2);
    
    // Both proposals get approved through governance
    await ApproveProposal(victimProposal);
    await ApproveProposal(attackerProposal);
    
    // Attacker's proposal deploys first
    var attackerContract = await ReleaseProposal(attackerProposal);
    
    // Victim's proposal now fails permanently with "contract code has already been deployed before"
    var exception = await Assert.ThrowsAsync<AssertionException>(
        () => ReleaseProposal(victimProposal)
    );
    Assert.Contains("contract code has already been deployed before", exception.Message);
    
    // Attacker owns the deployed contract
    var author = await GetContractAuthor(attackerContract);
    Assert.Equal(AttackerAddress, author);
}
```

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L124-124)
```csharp
        // AssertDeploymentProposerAuthority(Context.Sender);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L125-126)
```csharp
        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        AssertContractNotExists(codeHash);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L127-128)
```csharp
        var proposedContractInputHash = CalculateHashFromInput(input);
        RegisterContractProposingData(proposedContractInputHash);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L519-524)
```csharp
    public override Empty SetContractAuthor(SetContractAuthorInput input)
    {
        var info = State.ContractInfos[input.ContractAddress];
        Assert(info != null, "Contract not found.");
        var oldAuthor = info.Author;
        Assert(Context.Sender == info.Author, "No permission.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L21-22)
```csharp
        var codeHash = HashHelper.ComputeFrom(code);
        AssertContractNotExists(codeHash);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L71-71)
```csharp
        State.SmartContractRegistrations[reg.CodeHash] = reg;
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L98-102)
```csharp
    private void UpdateSmartContract(Address contractAddress, byte[] code, Address author, bool isUserContract)
    {
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        Assert(author == info.Author, "No permission.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L175-178)
```csharp
    private Hash CalculateHashFromInput(IMessage input)
    {
        return HashHelper.ComputeFrom(input);
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L204-215)
```csharp
    private void RegisterContractProposingData(Hash proposedContractInputHash)
    {
        var registered = State.ContractProposingInputMap[proposedContractInputHash];
        Assert(registered == null || Context.CurrentBlockTime >= registered.ExpiredTime, "Already proposed.");
        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();
        State.ContractProposingInputMap[proposedContractInputHash] = new ContractProposingInput
        {
            Proposer = Context.Sender,
            Status = ContractProposingInputStatus.Proposed,
            ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
        };
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L379-382)
```csharp
    private void AssertContractNotExists(Hash codeHash)
    {
        Assert(State.SmartContractRegistrations[codeHash] == null, "contract code has already been deployed before.");
    }
```

**File:** protobuf/acs0.proto (L156-162)
```text
message ContractDeploymentInput {
    // The category of contract code(0: C#).
    sint32 category = 1;
    // The byte array of the contract code.
    bytes code = 2;
    ContractOperation contract_operation = 3;
}
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroState.cs (L13-17)
```csharp
    public MappedState<Hash, SmartContractRegistration> SmartContractRegistrations { get; set; }

    public MappedState<Hash, Address> NameAddressMapping { get; set; }

    public MappedState<Hash, ContractProposingInput> ContractProposingInputMap { get; set; }
```
