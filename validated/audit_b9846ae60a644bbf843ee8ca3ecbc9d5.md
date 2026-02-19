# Audit Report

## Title
ConfigurationController Can Be Changed to Attacker-Controlled Contract Bypassing Organization-Based Governance

## Summary
The `ChangeConfigurationController` method in the Configuration contract lacks validation that the new controller's `ContractAddress` is a legitimate governance contract (Parliament, Association, or Referendum). An attacker can deploy a malicious contract with a fake `ValidateOrganizationExist` method that always returns true, then use a single governance proposal to permanently bypass multi-signature governance, gaining unilateral control over critical system configurations.

## Finding Description

**Root Cause - Insufficient Contract Address Validation:**

The `CheckOrganizationExist` method performs insufficient validation when changing the ConfigurationController. [1](#0-0) 

This method makes a cross-contract call to the `ContractAddress` specified in the `AuthorityInfo` parameter, calling its `ValidateOrganizationExist` method. However, it does NOT validate that the `ContractAddress` is one of the legitimate system governance contracts.

**Vulnerable Execution Path:**

1. The `ChangeConfigurationController` method only checks that the sender is the current controller and that `CheckOrganizationExist(input)` returns true. [2](#0-1) 

2. The ConfigurationController is lazily initialized to Parliament's default organization. [3](#0-2) 

3. When permissions are checked for `SetConfiguration`, the system only verifies the sender matches the controller's `OwnerAddress`, NOT the `ContractAddress`. [4](#0-3) 

**Why Existing Protections Fail:**

Legitimate governance contracts validate that organizations exist in their state mappings by checking `State.Organizations[input] != null`:
- Parliament: [5](#0-4) 
- Association: [6](#0-5) 
- Referendum: [7](#0-6) 

However, a malicious contract can implement `ValidateOrganizationExist` to always return true, bypassing this protection.

The codebase provides validation patterns to check if an address is a system contract:
- Using `ValidateSystemContractAddress`: [8](#0-7) 
- Using `GetSystemContractNameToAddressMapping`: [9](#0-8) 

**These patterns are NOT applied in `CheckOrganizationExist`, creating the vulnerability.**

## Impact Explanation

**Critical Governance Bypass:**

After a single governance approval, an attacker gains permanent unilateral control over the Configuration contract. The `SetConfiguration` method [10](#0-9)  manages critical system parameters including:

- `BlockTransactionLimit` - Controls maximum transactions per block, validated by [11](#0-10) 
- `RequiredAcsInContracts` - Defines required ACS standards for contract deployment, used by [12](#0-11) 

**Who Is Affected:**

- **All users:** System-wide configuration changes affect the entire blockchain
- **Contract developers:** RequiredAcsInContracts manipulation can block legitimate contracts or allow malicious ones
- **Network operators:** BlockTransactionLimit manipulation can cause DoS or enable spam attacks

**Severity Justification:**

This is **CRITICAL** because:
1. Completely bypasses the multi-signature organization-based governance model
2. Converts a decentralized governance system into single-address control
3. Enables unauthorized modification of critical system parameters without proposals, approvals, or oversight
4. Violates the core Authorization & Governance invariant that organization thresholds and authority must be enforced

## Likelihood Explanation

**Attack Complexity: MEDIUM**

The attack requires:
1. **Deploy malicious contract:** Users can deploy contracts on AElf through the ProposeNewContract workflow
2. **One governance approval:** Must get Parliament to approve a single proposal changing the ConfigurationController
3. **Social engineering:** The proposal could appear legitimate if disguised as "upgrading to an improved governance contract"

**Feasibility Conditions:**

- Initial governance approval barrier (medium-high)
- Could succeed through:
  * Compromised governance members
  * Social engineering ("upgrading to new governance contract")
  * Malicious proposal hidden in legitimate-looking changes
- After setup, exploitation is trivial (direct function calls)

**Detection Constraints:**

Governance members reviewing proposals may not recognize that:
- The new ContractAddress is not a legitimate system contract
- The check only validates that `ValidateOrganizationExist` exists, not that it's trustworthy
- Once approved, the change is permanent and irreversible through normal governance

**Economic Rationality:**

Attack cost is low (contract deployment + proposal submission). Potential gain is complete control over system configuration, enabling various attack vectors including parameter manipulation for profit or ransom scenarios.

## Recommendation

Add validation to ensure the `ContractAddress` in `AuthorityInfo` is a legitimate system governance contract before accepting controller changes. 

**Option 1: Validate against system contract mapping:**
```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate the contract address is a system contract
    var systemContractAddresses = Context.GetSystemContractNameToAddressMapping();
    var isSystemContract = systemContractAddresses.Values.Contains(authorityInfo.ContractAddress);
    Assert(isSystemContract, "Contract address must be a system contract.");
    
    // Validate against known governance contracts
    var isGovernanceContract = authorityInfo.ContractAddress == State.ParliamentContract.Value ||
                               authorityInfo.ContractAddress == Context.GetContractAddressByName(SmartContractConstants.AssociationContractSystemName) ||
                               authorityInfo.ContractAddress == Context.GetContractAddressByName(SmartContractConstants.ReferendumContractSystemName);
    Assert(isGovernanceContract, "Contract address must be a governance contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}
```

**Option 2: Use ValidateSystemContractAddress from Genesis contract:**
```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate the contract is Parliament, Association, or Referendum
    var parliamentHash = SmartContractConstants.ParliamentContractSystemHashName;
    var associationHash = SmartContractConstants.AssociationContractSystemHashName;
    var referendumHash = SmartContractConstants.ReferendumContractSystemHashName;
    
    var isValidGovernanceContract = 
        TryValidateSystemContract(authorityInfo.ContractAddress, parliamentHash) ||
        TryValidateSystemContract(authorityInfo.ContractAddress, associationHash) ||
        TryValidateSystemContract(authorityInfo.ContractAddress, referendumHash);
    
    Assert(isValidGovernanceContract, "Invalid governance contract address.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
        authorityInfo.OwnerAddress).Value;
}

private bool TryValidateSystemContract(Address contractAddress, Hash systemContractHashName)
{
    var expectedAddress = Context.GetContractAddressByName(systemContractHashName);
    return expectedAddress == contractAddress;
}
```

Apply this fix to both `ChangeConfigurationController` and `ChangeMethodFeeController` in the Configuration contract, and consider auditing other contracts that use similar patterns (Genesis, MultiToken, etc.).

## Proof of Concept

```csharp
[Fact]
public async Task ConfigurationController_Governance_Bypass_Attack()
{
    // Step 1: Deploy malicious contract with fake ValidateOrganizationExist
    var maliciousContractCode = ReadMaliciousContractCode(); // Returns true always
    var maliciousContractAddress = await DeployMaliciousContract(maliciousContractCode);
    
    // Step 2: Create proposal to change ConfigurationController to attacker's AuthorityInfo
    var attackerAddress = SampleAddress.AddressList[0];
    var maliciousAuthority = new AuthorityInfo
    {
        ContractAddress = maliciousContractAddress, // Malicious contract
        OwnerAddress = attackerAddress // Attacker's address
    };
    
    // Step 3: Get governance approval (simulating social engineering success)
    var proposalId = await CreateProposalAsync(ParliamentAddress, 
        nameof(ConfigurationImplContainer.ConfigurationImplStub.ChangeConfigurationController),
        maliciousAuthority);
    await ApproveWithMinersAsync(proposalId);
    var result = await ReleaseProposalAsync(proposalId);
    
    // Verify the malicious controller change succeeded
    result.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 4: Attacker now has unilateral control - bypass governance
    var maliciousConfig = new SetConfigurationInput
    {
        Key = "BlockTransactionLimit",
        Value = new Int32Value { Value = 1 }.ToByteString() // Set to 1 for DoS
    };
    
    // Attacker calls SetConfiguration directly without governance
    var attackResult = await ExecuteContractWithMiningAsync(
        ConfigurationContractAddress,
        nameof(ConfigurationImplContainer.ConfigurationImplStub.SetConfiguration),
        maliciousConfig,
        attackerAddress); // Using attacker's address directly
    
    // Verify governance was bypassed
    attackResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify configuration was changed without Parliament approval
    var newLimit = await GetConfiguration("BlockTransactionLimit");
    Int32Value.Parser.ParseFrom(newLimit.Value).Value.ShouldBe(1);
    
    // This proves complete governance bypass after single approval
}
```

### Citations

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L72-77)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract.cs (L10-21)
```csharp
    public override Empty SetConfiguration(SetConfigurationInput input)
    {
        AssertPerformedByConfigurationControllerOrZeroContract();
        Assert(input.Key.Any() && input.Value != ByteString.Empty, "Invalid set config input.");
        State.Configurations[input.Key] = new BytesValue { Value = input.Value };
        Context.Fire(new ConfigurationSet
        {
            Key = input.Key,
            Value = input.Value
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract.cs (L29-36)
```csharp
    public override Empty ChangeConfigurationController(AuthorityInfo input)
    {
        AssertPerformedByConfigurationController();
        Assert(input != null, "invalid input");
        Assert(CheckOrganizationExist(input), "Invalid authority input.");
        State.ConfigurationController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L8-19)
```csharp
    private AuthorityInfo GetDefaultConfigurationController()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L21-30)
```csharp
    private void AssertPerformedByConfigurationController()
    {
        if (State.ConfigurationController.Value == null)
        {
            var defaultConfigurationController = GetDefaultConfigurationController();
            State.ConfigurationController.Value = defaultConfigurationController;
        }

        Assert(Context.Sender == State.ConfigurationController.Value.OwnerAddress, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L51-54)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L218-221)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L59-64)
```csharp
    public override Empty ValidateSystemContractAddress(ValidateSystemContractAddressInput input)
    {
        var actualAddress = GetContractAddressByName(input.SystemContractHashName);
        Assert(actualAddress == input.Address, "Address not expected.");
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L200-203)
```csharp
        var systemContractAddresses = Context.GetSystemContractNameToAddressMapping().Values;
        var isSystemContractAddress = systemContractAddresses.Contains(Context.Sender);
        Assert(isInWhiteList || isSystemContractAddress, "No Permission.");
    }
```

**File:** src/AElf.Kernel/Miner/BlockTransactionLimitProvider.cs (L9-48)
```csharp
public interface IBlockTransactionLimitProvider
{
    Task<int> GetLimitAsync(IBlockIndex blockIndex);
    Task SetLimitAsync(IBlockIndex blockIndex, int limit);
}

internal class BlockTransactionLimitProvider : BlockExecutedDataBaseProvider<Int32Value>,
    IBlockTransactionLimitProvider,
    ISingletonDependency
{
    private const string BlockExecutedDataName = "BlockTransactionLimit";
    private readonly int _systemTransactionCount;

    public BlockTransactionLimitProvider(
        ICachedBlockchainExecutedDataService<Int32Value> cachedBlockchainExecutedDataService,
        IEnumerable<ISystemTransactionGenerator> systemTransactionGenerators) : base(
        cachedBlockchainExecutedDataService)
    {
        _systemTransactionCount = systemTransactionGenerators.Count();
    }

    public ILogger<BlockTransactionLimitProvider> Logger { get; set; }

    public Task<int> GetLimitAsync(IBlockIndex blockIndex)
    {
        var limit = GetBlockExecutedData(blockIndex);
        return Task.FromResult(limit?.Value ?? int.MaxValue);
    }

    public async Task SetLimitAsync(IBlockIndex blockIndex, int limit)
    {
        if (limit <= _systemTransactionCount)
            return;

        var blockTransactionLimit = new Int32Value
        {
            Value = limit
        };
        await AddBlockExecutedDataAsync(blockIndex, blockTransactionLimit);
        Logger.LogDebug($"BlockTransactionLimit has been changed to {limit}");
```

**File:** src/AElf.Kernel.CodeCheck/Infrastructure/RequiredAcsProvider.cs (L10-35)
```csharp
    private const string RequiredAcsInContractsConfigurationName = "RequiredAcsInContracts";
    private readonly IConfigurationService _configurationService;

    public RequiredAcsProvider(IConfigurationService configurationService)
    {
        _configurationService = configurationService;
    }

    public async Task<RequiredAcs> GetRequiredAcsInContractsAsync(Hash blockHash, long blockHeight)
    {
        var chainContext = new ChainContext
        {
            BlockHash = blockHash,
            BlockHeight = blockHeight
        };

        var returned =
            await _configurationService.GetConfigurationDataAsync(
                RequiredAcsInContractsConfigurationName, chainContext);

        var requiredAcsInContracts = new RequiredAcsInContracts();
        requiredAcsInContracts.MergeFrom(returned);
        return new RequiredAcs
        {
            AcsList = requiredAcsInContracts.AcsList.ToList(),
            RequireAll = requiredAcsInContracts.RequireAll
```
