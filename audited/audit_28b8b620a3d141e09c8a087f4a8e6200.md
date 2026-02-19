### Title
Contract Deployment Path Bypasses ACS Fee Standard Validation Allowing Fee-Free Transaction Execution

### Summary
The Genesis contract provides two deployment paths: `ProposeNewContract` and `DeployUserSmartContract`. The `ProposeNewContract` path deploys contracts with `IsUserContract=false`, which bypasses ACS standard validation during code check. This allows contracts to be deployed without implementing ACS1 or ACS12, causing fee-charging pre-execution plugins to never trigger, resulting in completely fee-free transaction execution.

### Finding Description

The vulnerability exists in the contract deployment flow through the Genesis contract (BasicContractZero). There are two distinct deployment paths with different validation behaviors:

**Path 1 - ProposeNewContract (Vulnerable)**: [1](#0-0) 

This method fires a `CodeCheckRequired` event that does NOT set `IsUserContract=true`: [2](#0-1) 

**Path 2 - DeployUserSmartContract (Secure)**: [3](#0-2) 

This method correctly fires `CodeCheckRequired` with `IsUserContract=true`: [4](#0-3) 

**Root Cause - ACS Validation Bypass**:

The code check service only validates ACS requirements when `isUserContract=true`: [5](#0-4) 

The event processor passes the `IsUserContract` flag from the event to the code check: [6](#0-5) 

**Fee Enforcement Failure**:

Fee charging is enforced via pre-execution plugins that check if contracts implement ACS1 or ACS12: [7](#0-6) [8](#0-7) 

The plugin checks if the contract implements the required ACS: [9](#0-8) 

If no plugin applies (contract implements neither ACS1 nor ACS12), no pre-transaction is generated: [10](#0-9) 

**Why Existing Protections Fail**:

The `ProposeNewContract` method has its authorization check commented out: [11](#0-10) 

While governance approval is still required through the proposal system, governance may approve contracts without realizing they lack fee-paying capability, as the distinction between deployment paths is not enforced by the protocol.

### Impact Explanation

**Direct Economic Impact**:
- **Complete fee bypass**: Contracts deployed via this path execute all transactions without paying any fees (neither base fees nor size fees)
- **Protocol revenue loss**: The blockchain loses 100% of transaction fee revenue from affected contracts
- **Economic attack vector**: Malicious actors can deploy high-volume contracts that consume network resources without compensation

**Who is Affected**:
- The protocol's economic sustainability (fee burn/distribution mechanisms)
- Legitimate users who pay fees while attackers do not
- Network resource allocation fairness

**Severity Justification**:
This is a HIGH severity vulnerability because:
1. Impact is direct and quantifiable (complete fee bypass)
2. It affects a critical protocol invariant (fee deduction paths must be enforced)
3. It creates unfair economic advantages and protocol revenue loss
4. Multiple contracts could be deployed this way, amplifying the impact

### Likelihood Explanation

**Attacker Capabilities Required**:
1. Ability to propose contracts (either be a parliament member/miner OR governance has `ProposerAuthorityRequired=false`)
2. Ability to get governance approval for the proposal

The governance approval requirement is documented here: [12](#0-11) 

**Attack Complexity**: MEDIUM
- Requires governance participation (proposal must be approved by miners/organization members)
- However, if governance doesn't understand the distinction between deployment paths
- Or if miners are themselves exploiting this (they can both propose and approve)
- Then the attack is feasible

**Feasibility Conditions**:
1. Governance is unaware of the security implications
2. OR Governance is compromised/collusion between miners
3. OR Organization has weak access controls (`ProposerAuthorityRequired=false`)

**Detection Constraints**:
The deployed contract will appear legitimate in most respects - only analysis of its ACS implementations would reveal the fee bypass.

**Probability Reasoning**:
Given that miners can both propose and approve, and the protocol design allows this path without explicit warnings or restrictions, the likelihood is MEDIUM-to-HIGH in environments where governance oversight is weak.

### Recommendation

**Immediate Fix**:

1. **Deprecate ProposeNewContract for user contracts**: Modify `ProposeNewContract` to reject non-system contracts or fire the event with `IsUserContract=true` for all non-system contracts:

```csharp
// In ProposeNewContract, change event firing:
Context.Fire(new CodeCheckRequired
{
    Code = input.Code,
    ProposedContractInputHash = proposedContractInputHash,
    Category = input.Category,
    IsSystemContract = false,
    IsUserContract = true  // <-- ADD THIS
});
```

2. **Enforce ACS validation**: Modify code check to validate ACS requirements for ALL non-system contracts: [13](#0-12) 

Change to:
```csharp
// Validate ACS for all non-system contracts
if (!isSystemContract)
{
    requiredAcs = await _requiredAcsProvider.GetRequiredAcsInContractsAsync(blockHash, blockHeight);
}
```

3. **Add invariant check**: In the deployment finalization, verify that non-system contracts implement required ACS standards.

**Test Cases**:
1. Attempt to deploy a contract without ACS1/ACS12 via `ProposeNewContract` - should FAIL code check
2. Verify that only `DeployUserSmartContract` can deploy user contracts successfully  
3. Test that all deployed user contracts have fee-charging pre-transactions generated
4. Verify backward compatibility for existing system contracts

### Proof of Concept

**Initial State**:
- Attacker is a parliament member (miner) OR organization has `ProposerAuthorityRequired=false`
- Governance contract is initialized and functional

**Attack Steps**:

1. **Deploy malicious contract code** (implements neither ACS1 nor ACS12):
   - Compile a simple contract with business logic but NO ACS implementations
   - Calculate code hash

2. **Propose contract via ProposeNewContract**:
   - Call `BasicContractZero.ProposeNewContract(ContractDeploymentInput)`
   - Event fires with `IsSystemContract=false`, `IsUserContract` defaults to `false`
   - Code check validates general safety but SKIPS ACS validation

3. **Approve proposal**:
   - As miner/parliament member, call `Parliament.Approve(proposalId)`
   - Reach approval threshold
   - Call `Parliament.Release(proposalId)`

4. **Contract deploys successfully**:
   - `ProposeContractCodeCheck` and `DeploySmartContract` execute
   - Contract deployed with `IsUserContract=false` stored in contract info

5. **Execute fee-free transactions**:
   - Call any method on the deployed contract
   - Pre-execution plugins check for ACS1/ACS12 implementation
   - Neither found → no plugin applies → NO pre-transaction generated
   - Transaction executes with ZERO fees charged

**Expected vs Actual Result**:
- **Expected**: All non-system contracts should pay transaction fees
- **Actual**: Contract executes without any fee charging mechanism triggered

**Success Condition**:
Transaction executes successfully with TransactionFee events showing 0 fees charged, while equivalent transactions to ACS1-implementing contracts show normal fee deduction.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L122-173)
```csharp
    public override Hash ProposeNewContract(ContractDeploymentInput input)
    {
        // AssertDeploymentProposerAuthority(Context.Sender);
        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        AssertContractNotExists(codeHash);
        var proposedContractInputHash = CalculateHashFromInput(input);
        RegisterContractProposingData(proposedContractInputHash);

        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();

        if (input.ContractOperation != null)
        {
            ValidateContractOperation(input.ContractOperation, 0, codeHash);
            
            // Remove one time signer if exists. Signer is only needed for validating signature.
            RemoveOneTimeSigner(input.ContractOperation.Deployer);
            
            AssertContractAddressAvailable(input.ContractOperation.Deployer, input.ContractOperation.Salt);
        }

        // Create proposal for deployment
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput = new CreateProposalInput
            {
                ToAddress = Context.Self,
                ContractMethodName =
                    nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.ProposeContractCodeCheck),
                Params = new ContractCodeCheckInput
                {
                    ContractInput = input.ToByteString(),
                    CodeCheckReleaseMethod = nameof(DeploySmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = input.Category,
                    IsSystemContract = false
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput.ToByteString());

        Context.Fire(new ContractProposed
        {
            ProposedContractInputHash = proposedContractInputHash
        });

        return proposedContractInputHash;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L409-443)
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

        // Fire event to trigger BPs checking contract code
        Context.Fire(new CodeCheckRequired
        {
            Code = input.Code,
            ProposedContractInputHash = proposedContractInputHash,
            Category = input.Category,
            IsSystemContract = false,
            IsUserContract = true
        });

        return new DeployUserSmartContractOutput
        {
            CodeHash = codeHash
        };
    }
```

**File:** src/AElf.Kernel.CodeCheck/Application/CodeCheckService.cs (L31-40)
```csharp
        var requiredAcs = new RequiredAcs
        {
            AcsList = new List<string>(),
            RequireAll = false
        };
        
        if (isUserContract)
        {
            requiredAcs = await _requiredAcsProvider.GetRequiredAcsInContractsAsync(blockHash, blockHeight);
        }
```

**File:** src/AElf.Kernel.CodeCheck/CodeCheckRequiredLogEventProcessor.cs (L59-69)
```csharp
                    var codeCheckJob = new CodeCheckJob
                    {
                        BlockHash = block.GetHash(),
                        BlockHeight = block.Height,
                        ContractCode = code,
                        ContractCategory = eventData.Category,
                        IsSystemContract = eventData.IsSystemContract,
                        IsUserContract = eventData.IsUserContract,
                        CodeCheckProposalId = proposalId,
                        ProposedContractInputHash = eventData.ProposedContractInputHash
                    };
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/FeeChargePreExecutionPlugin.cs (L19-23)
```csharp
    protected override bool IsApplicableToTransaction(IReadOnlyList<ServiceDescriptor> descriptors, Transaction transaction,
        Address tokenContractAddress)
    {
        return HasApplicableAcs(descriptors) || transaction.To == tokenContractAddress;
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/UserContractFeeChargePreExecutionPlugin.cs (L20-23)
```csharp
    protected override bool IsApplicableToTransaction(IReadOnlyList<ServiceDescriptor> descriptors, Transaction transaction, Address tokenContractAddress)
    {
        return HasApplicableAcs(descriptors);
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractExecutionPluginBase.cs (L16-19)
```csharp
    protected bool HasApplicableAcs(IReadOnlyList<ServiceDescriptor> descriptors)
    {
        return descriptors.Any(service => service.File.GetIdentity() == _acsSymbol);
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L77-78)
```csharp
            if (!IsApplicableToTransaction(descriptors, transactionContext.Transaction, tokenContractAddress))
                return new List<Transaction>();
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L22-34)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        // It is a valid proposer if
        // authority check is disable,
        // or sender is in proposer white list,
        // or sender is one of miners when member proposing allowed.
        Assert(
            !organization.ProposerAuthorityRequired || ValidateAddressInWhiteList(proposer) ||
            (organization.ParliamentMemberProposingAllowed && ValidateParliamentMemberAuthority(proposer)),
            "Unauthorized to propose.");
    }
```
