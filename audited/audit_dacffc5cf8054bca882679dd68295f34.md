### Title
Authorization Bypass in DeploySystemSmartContract Allows Arbitrary System Contract Deployment on Non-Production Chains

### Summary
When a chain is initialized with `ContractDeploymentAuthorityRequired` set to false (test networks, custom networks), any address can call `DeploySystemSmartContract()` to deploy arbitrary contracts marked as system contracts without authorization. This bypasses the intended restriction that system contract deployment should only occur during genesis setup or through proper governance channels.

### Finding Description

The vulnerability exists in the `DeploySystemSmartContract()` function where authorization logic incorrectly allows unrestricted system contract deployment when `ContractDeploymentAuthorityRequired` is false. [1](#0-0) 

The assertion at line 104 checks: `Assert(!State.Initialized.Value || !State.ContractDeploymentAuthorityRequired.Value)`. When the chain is initialized with `ContractDeploymentAuthorityRequired = false`, this evaluates to `Assert(false || true) = Assert(true)`, allowing the function to proceed. [2](#0-1) 

The `RequireSenderAuthority()` function at line 106 then executes. Since `State.Initialized.Value = true`, it skips the genesis-only check. With `isGenesisOwnerAuthorityRequired = false`, the function returns immediately at line 157 without performing ANY sender authorization check.

The contract is then deployed directly via `DeploySmartContract()` at line 113 with:
- `isSystemContract = true` 
- `author = Context.Sender` (the attacker's address)
- No code check or governance approval process [3](#0-2) 

The deployed contract receives the `IsSystemContract` flag at line 48, granting it privileged status.

### Impact Explanation

**Direct Security Impact:**
System contracts receive special privileges that bypass security restrictions applied to regular contracts. An attacker can deploy malicious code that:

1. **Access Restricted APIs**: System contracts can use APIs like cryptographic functions that are whitelisted only for system contracts, as documented in the code checking infrastructure
2. **Impersonate System Contracts**: Deploy contracts with confusing names similar to legitimate system contracts
3. **Execute Inline Transactions**: The attacker can specify `transaction_method_call_list` to execute initialization transactions immediately after deployment [4](#0-3) 

**Affected Environments:**
According to the deployment documentation, `ContractDeploymentAuthorityRequired` is false in:
- Contract unit tests
- Custom/private networks
- Development environments [5](#0-4) 

While production networks (mainnet/testnet) are documented to always use `ContractDeploymentAuthorityRequired = true`, custom enterprise deployments and development chains with real test assets remain vulnerable.

### Likelihood Explanation

**Exploitability Assessment:**

The vulnerability is directly exploitable in chains where `ContractDeploymentAuthorityRequired = false`:

1. **Entry Point**: The `DeploySystemSmartContract()` function is publicly callable (no access modifiers restrict it)
2. **Preconditions**: Requires only that the chain was initialized with `ContractDeploymentAuthorityRequired = false`
3. **Attack Complexity**: Low - single transaction with arbitrary contract bytecode
4. **Detection**: Difficult to detect without monitoring all contract deployments for the `IsSystemContract` flag [6](#0-5) 

The `ContractDeploymentAuthorityRequired` value is set during initialization and cannot be changed afterward. [7](#0-6) 

**Likelihood Limitation:**
Production networks (mainnet/testnet) have `ContractDeploymentAuthorityRequired = true` by default, making them immune. However, custom private chains, development environments, and test networks with this setting disabled remain vulnerable.

### Recommendation

**Immediate Fix:**
Modify `DeploySystemSmartContract()` to ALWAYS require proper authorization for system contract deployment, regardless of the `ContractDeploymentAuthorityRequired` setting:

```
Assert(!State.Initialized.Value, "System contract deployment only allowed during genesis.");
```

Replace the current OR condition with a strict check that only allows system contract deployment before initialization completes.

**Alternative Fix:**
Keep the existing assertion but fix `RequireSenderAuthority()` to always enforce authorization when called from `DeploySystemSmartContract()` by passing a required address parameter:

```
RequireSenderAuthority(Context.Self);  // Only genesis contract itself
```

**Additional Safeguards:**
1. Add explicit events for system contract deployments to aid monitoring
2. Implement a separate governance-controlled flag specifically for system contract deployment authority
3. Add integration tests verifying that post-initialization system contract deployment fails even with `ContractDeploymentAuthorityRequired = false`

### Proof of Concept

**Initial State:**
- Chain initialized with `ContractDeploymentAuthorityRequired = false` (test/custom network)
- `State.Initialized.Value = true`
- `State.ContractDeploymentAuthorityRequired.Value = false`

**Attack Sequence:**

1. Attacker prepares malicious contract bytecode compiled with system contract privileges
2. Attacker constructs `SystemContractDeploymentInput`:
   - `category = 0` (C# contract)
   - `code = [malicious_bytecode]`
   - `name = Hash.LoadFromHex("custom_system_contract")`
   - `transaction_method_call_list = [initialization_calls]`

3. Attacker calls `DeploySystemSmartContract(input)` from any address

**Expected Result:** Transaction should fail with "Unauthorized" or similar error

**Actual Result:** 
- Assertion at line 104 passes: `!true || !false = false || true = true`
- `RequireSenderAuthority()` returns immediately without checks
- Malicious contract deployed with `IsSystemContract = true`
- Contract registered with attacker as author
- Initialization transactions execute
- `ContractDeployed` event fires with attacker's address as author

**Success Verification:**
Query `GetContractInfo()` for the deployed address - the `IsSystemContract` field will be `true` and `Author` will be the attacker's address, confirming unauthorized system contract deployment.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L102-120)
```csharp
    public override Address DeploySystemSmartContract(SystemContractDeploymentInput input)
    {
        Assert(!State.Initialized.Value || !State.ContractDeploymentAuthorityRequired.Value,
            "System contract deployment failed.");
        RequireSenderAuthority();
        var name = input.Name;
        var category = input.Category;
        var code = input.Code.ToByteArray();
        var transactionMethodCallList = input.TransactionMethodCallList;

        // Context.Sender should be identical to Genesis contract address before initialization in production
        var address = DeploySmartContract(name, category, code, true, Context.Sender, false);

        if (transactionMethodCallList != null)
            foreach (var methodCall in transactionMethodCallList.Value)
                Context.SendInline(address, methodCall.MethodName, methodCall.Params);

        return address;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L339-346)
```csharp
    public override Empty Initialize(InitializeInput input)
    {
        Assert(!State.Initialized.Value, "Contract zero already initialized.");
        Assert(Context.Sender == Context.Self, "No permission.");
        State.ContractDeploymentAuthorityRequired.Value = input.ContractDeploymentAuthorityRequired;
        State.Initialized.Value = true;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L15-96)
```csharp
    private Address DeploySmartContract(Hash name, int category, byte[] code, bool isSystemContract,
        Address author, bool isUserContract, Address deployer = null, Hash salt = null)
    {
        if (name != null)
            Assert(State.NameAddressMapping[name] == null, "contract name has already been registered before");

        var codeHash = HashHelper.ComputeFrom(code);
        AssertContractNotExists(codeHash);

        long serialNumber;
        Address contractAddress;

        if (salt == null)
        {
            serialNumber = State.ContractSerialNumber.Value;
            // Increment
            State.ContractSerialNumber.Value = serialNumber + 1;
            contractAddress = AddressHelper.ComputeContractAddress(Context.ChainId, serialNumber);
        }
        else
        {
            serialNumber = 0;
            contractAddress = AddressHelper.ComputeContractAddress(deployer, salt);
        }

        Assert(State.ContractInfos[contractAddress] == null, "Contract address exists.");

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

        var reg = new SmartContractRegistration
        {
            Category = category,
            Code = ByteString.CopyFrom(code),
            CodeHash = codeHash,
            IsSystemContract = info.IsSystemContract,
            Version = info.Version,
            ContractAddress = contractAddress,
            IsUserContract = isUserContract
        };

        var contractInfo = Context.DeploySmartContract(contractAddress, reg, name);

        info.ContractVersion = contractInfo.ContractVersion;
        reg.ContractVersion = info.ContractVersion;

        State.ContractInfos[contractAddress] = info;
        State.SmartContractRegistrations[reg.CodeHash] = reg;

        Context.Fire(new ContractDeployed
        {
            CodeHash = codeHash,
            Address = contractAddress,
            Author = author,
            Version = info.Version,
            Name = name,
            ContractVersion = info.ContractVersion,
            Deployer = deployer
        });

        Context.LogDebug(() => "BasicContractZero - Deployment ContractHash: " + codeHash.ToHex());
        Context.LogDebug(() => "BasicContractZero - Deployment success: " + contractAddress.ToBase58());

        if (name != null)
            State.NameAddressMapping[name] = contractAddress;

        var contractCodeHashList =
            State.ContractCodeHashListMap[Context.CurrentHeight] ?? new ContractCodeHashList();
        contractCodeHashList.Value.Add(codeHash);
        State.ContractCodeHashListMap[Context.CurrentHeight] = contractCodeHashList;

        return contractAddress;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L146-161)
```csharp
    private void RequireSenderAuthority(Address address = null)
    {
        if (!State.Initialized.Value)
        {
            // only authority of contract zero is valid before initialization
            AssertSenderAddressWith(Context.Self);
            return;
        }

        var isGenesisOwnerAuthorityRequired = State.ContractDeploymentAuthorityRequired.Value;
        if (!isGenesisOwnerAuthorityRequired)
            return;

        if (address != null)
            AssertSenderAddressWith(address);
    }
```

**File:** protobuf/acs0.proto (L179-199)
```text
message SystemContractDeploymentInput {
    message SystemTransactionMethodCall {
        // The method name of system transaction.
        string method_name = 1;
        // The params of system transaction method.
        bytes params = 2;
    }
    message SystemTransactionMethodCallList {
        // The list of system transactions.
        repeated SystemTransactionMethodCall value = 1;
    }
    // The category of contract code(0: C#).
    sint32 category = 1;
    // The byte array of the contract code.
    bytes code = 2;
    // The name of the contract. It has to be unique.
    aelf.Hash name = 3;
    // An initial list of transactions for the system contract,
    // which is executed in sequence when the contract is deployed.
    SystemTransactionMethodCallList transaction_method_call_list = 4;
}
```

**File:** docs-sphinx/getting-started/smart-contract-development/deployment.md (L7-21)
```markdown
For contract deployment, what matters is the `ContractDeploymentAuthorityRequired` option in the `ContractOptions` for this network. 
It is determined since the launch of the chain. 

- if `ContractDeploymentAuthorityRequired` is false, anyone can directly deploy contract with transaction 
- Only account with specific authority is permitted to deploy contract if `ContractDeploymentAuthorityRequired` is true

This part will introduce contract deployment pipeline for different chain type on AElf mainnet/testnet/customnet network. 

## Authority check

### `ContractDeploymentAuthorityRequired` is false

Anyone can directly deploy contract with transaction if `ContractDeploymentAuthorityRequired` is false. 
It is usually set as false especially when it is for contract unit test or custom network. 

```

**File:** src/AElf.Kernel.SmartContract/ContractOptions.cs (L3-7)
```csharp
public class ContractOptions
{
    public bool ContractDeploymentAuthorityRequired { get; set; } = true;
    public string GenesisContractDir { get; set; }
}
```
