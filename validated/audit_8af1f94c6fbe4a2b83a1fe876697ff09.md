# Audit Report

## Title
Unprotected Initialization Function Enables Manager Control Hijacking During System Deployment

## Summary
The `InitialMiningRewardProfitItem()` function in the Treasury contract lacks access control, allowing any caller to execute it before legitimate initialization. If invoked before the Election contract is deployed, the manager transfer for SubsidyHash and WelfareHash schemes fails silently, permanently locking these schemes under Treasury management instead of Election control, breaking the election reward distribution system.

## Finding Description

The vulnerability exists in the `InitialMiningRewardProfitItem()` function which performs critical one-time initialization to transfer profit scheme management rights. The function has three critical flaws:

**1. Missing Access Control:**
The function is publicly accessible with no sender authorization check. It only verifies one-time execution via a state flag check, but does NOT verify the caller's identity. [1](#0-0) 

The protobuf definition confirms there is no access control annotation (no `is_system` option): [2](#0-1) 

**2. Silent Failure on Null Address:**
When `GetContractAddressByName` returns null (Election contract not yet registered), the conditional check causes manager transfer to be skipped without error, leaving schemes under Treasury control: [3](#0-2) 

**3. Irreversible State Lock:**
Once called, the function cannot execute again as the state flag is set at line 90. The Treasury contract provides no alternative method to transfer manager rights (ResetManager is only called within this function). [4](#0-3) 

**Execution Path:**
1. Attacker monitors for `InitialTreasuryContract` transaction (creates 7 schemes with Treasury as manager)
2. Before Election contract deployment/registration, attacker calls `InitialMiningRewardProfitItem`
3. `GetContractAddressByName(SmartContractConstants.ElectionContractSystemName)` returns null
4. Manager transfer skipped, SubsidyHash and WelfareHash remain under Treasury control
5. State flag set, function permanently locked
6. Later Election contract deployment cannot obtain required manager role

**Downstream Impact:**
The Election contract requires manager role to add/remove beneficiaries for voter welfare: [5](#0-4) [6](#0-5) 

And for candidate subsidies: [7](#0-6) [8](#0-7) 

The Profit contract enforces manager-only access for these operations: [9](#0-8) [10](#0-9) 

The Economic contract initialization expects these schemes under Election management: [11](#0-10) 

When schemes remain under Treasury, lines 206-207 will retrieve incorrect scheme IDs, causing Economic initialization to fail or use wrong scheme IDs.

## Impact Explanation

**Operational Disruption:**
- Election contract cannot add voters as welfare beneficiaries → voters receive no staking rewards
- Election contract cannot add candidates to subsidy scheme → candidates receive no backup rewards
- Core election incentive mechanism completely broken
- Economic contract initialization fails or uses incorrect scheme IDs

**Affected Parties:**
- All network voters expecting welfare rewards from locked tokens
- All candidate node operators expecting subsidy payments
- Network governance relying on functioning election incentives

**Severity Justification:**
While not direct fund theft, this breaks a critical economic subsystem. The election reward distribution represents a significant portion of network incentives. Though recoverable via contract upgrade, this requires governance proposal and voting delay, contract redeployment and migration, service disruption during remediation, and potential loss of user confidence.

This constitutes a **HIGH** severity operational denial-of-service against the election subsystem.

## Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required
- Single transaction call to public function
- Gas cost negligible (standard function call)

**Attack Complexity:**
LOW - Attacker only needs to:
1. Monitor mempool for `InitialTreasuryContract` transaction
2. Submit `InitialMiningRewardProfitItem` transaction before legitimate initialization
3. No complex state manipulation or multi-step coordination required

**Feasibility Conditions:**
While in production mainnet with proper atomic genesis block initialization (Election deployed before Treasury per deployment order), the attack window is minimal, the vulnerability still exists because: [12](#0-11) 

- Testnet deployments often use manual initialization via separate transactions
- Contract upgrade scenarios may not maintain strict initialization ordering
- Development environments with manual setup are vulnerable
- The lack of authorization violates defense-in-depth principles

**Probability Assessment:**
MEDIUM - Likelihood varies by deployment context:
- Production mainnet with atomic genesis → LOW
- Testnet/development/upgrade scenarios → HIGH
- Front-running during initialization is a known attack vector

**Economic Rationality:**
Griefing attack with asymmetric cost/damage ratio:
- Attacker cost: Single transaction fee (~0.1 ELF)
- Protocol damage: Complete election subsystem failure requiring upgrade
- Motivation: Competitor sabotage, ransom demands, or network disruption

## Recommendation

Add proper access control to the `InitialMiningRewardProfitItem()` function. The function should verify that the caller is either:
1. The Genesis contract (Zero contract) during initialization, OR
2. The contract owner/deployer

Recommended fix:
```csharp
public override Empty InitialMiningRewardProfitItem(Empty input)
{
    // Add authorization check
    if (State.ZeroContract.Value == null)
        State.ZeroContract.Value = Context.GetZeroSmartContractAddress();
    
    Assert(
        Context.Sender == State.ZeroContract.Value || 
        Context.Sender == State.ZeroContract.GetContractAuthor.Call(Context.Self),
        "No permission to initialize."
    );
    
    Assert(State.TreasuryHash.Value == null, "Already initialized.");
    // ... rest of the function
}
```

Additionally, consider making the manager transfer failure explicit by throwing an assertion error if Election contract is not registered, rather than silently skipping the operation.

## Proof of Concept

```csharp
// This test demonstrates the vulnerability
[Fact]
public async Task InitialMiningRewardProfitItem_CanBeCalledByAnyone_BeforeElectionDeployment()
{
    // Setup: Deploy Treasury contract and call InitialTreasuryContract
    await TreasuryContractStub.InitialTreasuryContract.SendAsync(new Empty());
    
    // Attack: Attacker calls InitialMiningRewardProfitItem BEFORE Election is deployed
    // No authorization check prevents this
    var attackerStub = GetTreasuryContractStub(Accounts[1].KeyPair);
    var result = await attackerStub.InitialMiningRewardProfitItem.SendAsync(new Empty());
    
    // Verify: Function executed successfully
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Schemes remain under Treasury management (not transferred to Election)
    var treasurySchemeId = await TreasuryContractStub.GetTreasurySchemeId.CallAsync(new Empty());
    var schemeInfo = await ProfitContractStub.GetScheme.CallAsync(treasurySchemeId);
    
    // SubsidyHash and WelfareHash are still managed by Treasury instead of Election
    var managingSchemes = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = TreasuryContractAddress });
    
    // This should contain SubsidyHash and WelfareHash, proving they weren't transferred
    managingSchemes.SchemeIds.Count.ShouldBe(7); // All 7 schemes still under Treasury
    
    // Now even if Election deploys later, it cannot manage these schemes
    // The state flag prevents re-execution of the initialization
}
```

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L80-82)
```csharp
    public override Empty InitialMiningRewardProfitItem(Empty input)
    {
        Assert(State.TreasuryHash.Value == null, "Already initialized.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L90-96)
```csharp
        State.TreasuryHash.Value = managingSchemeIds[0];
        State.RewardHash.Value = managingSchemeIds[1];
        State.SubsidyHash.Value = managingSchemeIds[2];
        State.WelfareHash.Value = managingSchemeIds[3];
        State.BasicRewardHash.Value = managingSchemeIds[4];
        State.VotesWeightRewardHash.Value = managingSchemeIds[5];
        State.ReElectionRewardHash.Value = managingSchemeIds[6];
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L98-112)
```csharp
        var electionContractAddress =
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        if (electionContractAddress != null)
        {
            State.ProfitContract.ResetManager.Send(new ResetManagerInput
            {
                SchemeId = managingSchemeIds[2],
                NewManager = electionContractAddress
            });
            State.ProfitContract.ResetManager.Send(new ResetManagerInput
            {
                SchemeId = managingSchemeIds[3],
                NewManager = electionContractAddress
            });
        }
```

**File:** protobuf/treasury_contract.proto (L23-25)
```text
    // Initialize the sub-item of the bonus scheme.
    rpc InitialMiningRewardProfitItem (google.protobuf.Empty) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L304-311)
```csharp
    private void RemoveBeneficiaryOfVoter(Address voterAddress = null)
    {
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            Beneficiary = voterAddress ?? Context.Sender
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L369-383)
```csharp
    private void AddBeneficiaryToVoter(long votesWeight, long lockSeconds, Hash voteId)
    {
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = votesWeight
            },
            EndPeriod = GetEndPeriod(lockSeconds),
            // one vote, one profit detail, so voteId equals to profitDetailId
            ProfitDetailId = voteId
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L781-795)
```csharp
    private void AddBeneficiary(string candidatePubkey, Address profitsReceiver = null)
    {
        var beneficiaryAddress = GetBeneficiaryAddress(candidatePubkey, profitsReceiver);
        var subsidyId = GenerateSubsidyId(candidatePubkey, beneficiaryAddress);
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.SubsidyHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = beneficiaryAddress,
                Shares = 1,
            },
            ProfitDetailId = subsidyId
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L797-807)
```csharp
    private void RemoveBeneficiary(string candidatePubkey, Address profitsReceiver = null)
    {
        var beneficiaryAddress = GetBeneficiaryAddress(candidatePubkey, profitsReceiver);
        var previousSubsidyId = GenerateSubsidyId(candidatePubkey, beneficiaryAddress);
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.SubsidyHash.Value,
            Beneficiary = beneficiaryAddress,
            ProfitDetailId = previousSubsidyId
        });
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-174)
```csharp
    public override Empty AddBeneficiary(AddBeneficiaryInput input)
    {
        AssertValidInput(input);
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;

        var schemeId = input.SchemeId;
        var scheme = State.SchemeInfos[schemeId];

        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-239)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();

        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L187-209)
```csharp
    private void SetTreasurySchemeIdsToElectionContract()
    {
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
        var schemeIdsManagingByTreasuryContract = State.ProfitContract.GetManagingSchemeIds.Call(
            new GetManagingSchemeIdsInput
            {
                Manager = Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName)
            }).SchemeIds;
        var schemeIdsManagingByElectionContract = State.ProfitContract.GetManagingSchemeIds.Call(
            new GetManagingSchemeIdsInput
            {
                Manager = Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName)
            }).SchemeIds;
        State.ElectionContract.SetTreasurySchemeIds.Send(new SetTreasurySchemeIdsInput
        {
            TreasuryHash = schemeIdsManagingByTreasuryContract[0],
            WelcomeHash = schemeIdsManagingByTreasuryContract[3],
            FlexibleHash = schemeIdsManagingByTreasuryContract[4],
            SubsidyHash = schemeIdsManagingByElectionContract[0],
            WelfareHash = schemeIdsManagingByElectionContract[1]
        });
    }
```

**File:** src/AElf.OS.Core/Node/Application/OsBlockchainNodeContextService.cs (L40-78)
```csharp
    public async Task<OsBlockchainNodeContext> StartAsync(OsBlockchainNodeContextStartDto dto)
    {
        var transactions = new List<Transaction>();

        transactions.Add(GetTransactionForDeployment(dto.ZeroSmartContract,
            ZeroSmartContractAddressNameProvider.Name,
            dto.SmartContractRunnerCategory));

        transactions.AddRange(dto.InitializationSmartContracts
            .Select(p => GetTransactionForDeployment(p.Code, p.SystemSmartContractName,
                dto.SmartContractRunnerCategory,
                p.ContractInitializationMethodCallList)));

        if (dto.InitializationTransactions != null)
            transactions.AddRange(dto.InitializationTransactions);

        // Add transaction for initialization
        transactions.Add(GetTransactionForGenesisOwnerInitialization(dto));

        var blockchainNodeContextStartDto = new BlockchainNodeContextStartDto
        {
            ChainId = dto.ChainId,
            ZeroSmartContractType = dto.ZeroSmartContract,
            Transactions = transactions.ToArray()
        };

        var context = new OsBlockchainNodeContext
        {
            BlockchainNodeContext =
                await _blockchainNodeContextService.StartAsync(blockchainNodeContextStartDto),
            AElfNetworkServer = _networkServer
        };

        await _networkServer.StartAsync();

        foreach (var nodePlugin in _nodePlugins) await nodePlugin.StartAsync(dto.ChainId);

        return context;
    }
```
