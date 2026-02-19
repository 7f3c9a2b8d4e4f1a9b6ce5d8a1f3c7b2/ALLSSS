### Title
Controller Takeover via Unvalidated Governance Contract Address in ChangeContractDeploymentController

### Summary
The `ChangeContractDeploymentController` function fails to validate that the provided `AuthorityInfo.ContractAddress` is a legitimate governance contract (Parliament, Association, or Referendum). An attacker can deploy a malicious contract with a `ValidateOrganizationExist` method that always returns true, then propose a controller change through legitimate governance that, if approved, permanently replaces the multi-sig governance with single-party control.

### Finding Description

The vulnerability exists in the `ChangeContractDeploymentController` function [1](#0-0)  which accepts an `AuthorityInfo` input containing both a `ContractAddress` and `OwnerAddress`.

The function performs only two validations:
1. Verifies the sender is the current controller's owner address
2. Calls `CheckOrganizationExist(input)` to validate the organization exists

The `CheckOrganizationExist` helper method [2](#0-1)  makes a cross-contract call to `authorityInfo.ContractAddress.ValidateOrganizationExist(authorityInfo.OwnerAddress)` without any validation that `ContractAddress` is one of the three legitimate governance contracts.

Legitimate governance contracts implement `ValidateOrganizationExist` to check if an organization is registered in their state [3](#0-2) . However, the system has no whitelist or registry check to ensure the `ContractAddress` parameter points to Parliament, Association, or Referendum [4](#0-3) .

**Exploitation Path:**
1. Attacker deploys a malicious contract with a `ValidateOrganizationExist` method that unconditionally returns `true`
2. Attacker creates a governance proposal to change the deployment controller, specifying their malicious contract as `ContractAddress` and an attacker-controlled address as `OwnerAddress`
3. If the proposal passes (potentially through social engineering or misleading presentation), the `CheckOrganizationExist` call succeeds because the malicious contract returns true
4. The controller is permanently changed to the attacker's setup, bypassing all future governance requirements

### Impact Explanation

**Critical Governance Bypass:**
- The ContractDeploymentController has authority over all contract deployments and updates on the blockchain [5](#0-4) 
- Once compromised, the attacker can deploy arbitrary malicious contracts without multi-sig approval or voting requirements
- The attacker can also change the CodeCheckController similarly [6](#0-5) , gaining complete control over contract code verification

**Affected Parties:**
- All blockchain users whose assets and operations depend on contract integrity
- The entire governance system's legitimacy and security model
- Protocol-level security as malicious contracts can be deployed to exploit other vulnerabilities

**Severity Justification:**
This violates the critical invariant that "Organization thresholds, proposer whitelist checks, proposal lifetime/expiration, correct organization hash resolution" must be enforced for governance operations. The attacker gains permanent, unilateral control over one of the most privileged operations in the system.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to deploy a contract (requires going through existing code check process once)
- Ability to create a governance proposal (may require being in proposer whitelist depending on configuration)
- Social engineering or sufficient voting power to get the malicious proposal approved

**Attack Complexity:**
- **Medium**: The malicious contract code is trivial (single method returning true), but requires governance approval
- The attack vector relies on governance participants not recognizing that the `ContractAddress` points to an unauthorized contract rather than Parliament/Association/Referendum
- The test suite only validates with legitimate contract addresses [7](#0-6) , suggesting this attack vector was not considered

**Feasibility:**
- **High**: If an attacker can obtain initial governance approval through legitimate or deceptive means, the exploit is straightforward
- Once executed, the takeover is permanent unless a subsequent governance action restores legitimate control
- No transaction-level detection mechanisms exist to flag invalid governance contract addresses

**Economic Rationality:**
The cost of deploying one malicious contract and creating a proposal is negligible compared to the total control gained over all future contract deployments.

### Recommendation

**Immediate Fix:**
Add validation in `ChangeContractDeploymentController` and `ChangeCodeCheckController` to ensure the `ContractAddress` is one of the legitimate governance contracts:

```csharp
private void ValidateGovernanceContract(Address contractAddress)
{
    var parliamentAddress = Context.GetContractAddressByName(
        SmartContractConstants.ParliamentContractSystemName);
    var associationAddress = Context.GetContractAddressByName(
        SmartContractConstants.AssociationContractSystemName);
    var referendumAddress = Context.GetContractAddressByName(
        SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        contractAddress == parliamentAddress || 
        contractAddress == associationAddress || 
        contractAddress == referendumAddress,
        "Invalid governance contract address.");
}
```

Call this method in both controller change functions before `CheckOrganizationExist`.

**Additional Protections:**
- Add similar validation to any other functions that accept `AuthorityInfo` parameters for authorization changes
- Add integration tests that attempt to use non-governance contracts as controllers and verify rejection
- Consider adding events that log controller changes with full details for monitoring

### Proof of Concept

**Initial State:**
- Genesis contract initialized with Parliament as ContractDeploymentController
- Current governance requires multi-sig approval from miners

**Attack Steps:**

1. **Deploy Malicious Contract:**
```
MaliciousContract.ValidateOrganizationExist(Address) returns BoolValue { Value = true }
```

2. **Create Governance Proposal:**
    - Call `ProposeNewContract` or similar to get the malicious contract deployed (if code check passes basic validation)
    - Create proposal through Parliament to call `ChangeContractDeploymentController` with:
  - `AuthorityInfo.ContractAddress = MaliciousContractAddress`
  - `AuthorityInfo.OwnerAddress = AttackerAddress`

3. **Get Proposal Approved:**
    - Use social engineering: "We're upgrading to a new governance model" or "Temporary controller for emergency fixes"
    - Miners approve and release the proposal

4. **Controller Changed:**
    - `CheckOrganizationExist` calls `MaliciousContract.ValidateOrganizationExist(AttackerAddress)`
    - Returns `true`, validation passes
    - `State.ContractDeploymentController.Value` is set to attacker's `AuthorityInfo`

**Expected Result:**
Proposal should be rejected due to invalid governance contract address

**Actual Result:**
Proposal succeeds, controller is changed to attacker's setup, future deployments require only attacker's approval

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L366-373)
```csharp
    public override Empty ChangeContractDeploymentController(AuthorityInfo input)
    {
        AssertSenderAddressWith(State.ContractDeploymentController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");
        State.ContractDeploymentController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L375-382)
```csharp
    public override Empty ChangeCodeCheckController(AuthorityInfo input)
    {
        AssertSenderAddressWith(State.CodeCheckController.Value.OwnerAddress);
        Assert(CheckOrganizationExist(input),
            "Invalid authority input.");
        State.CodeCheckController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L180-185)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L18-36)
```csharp
    public static readonly Hash ParliamentContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Parliament");

    public static readonly Hash VoteContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Vote");
    public static readonly Hash ProfitContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Profit");

    public static readonly Hash CrossChainContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.CrossChain");

    public static readonly Hash TokenConverterContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.TokenConverter");

    public static readonly Hash EconomicContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Economic");

    public static readonly Hash ReferendumContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Referendum");

    public static readonly Hash AssociationContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Association");
```

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L751-778)
```csharp
    public async Task ChangeContractZeroOwner_Test()
    {
        var createOrganizationResult = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateOrganization),
            new CreateOrganizationInput
            {
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = 1000,
                    MinimalVoteThreshold = 1000
                }
            });

        var organizationAddress = Address.Parser.ParseFrom(createOrganizationResult.ReturnValue);

        var contractDeploymentController = await GetContractDeploymentController(Tester, BasicContractZeroAddress);
        const string proposalCreationMethodName =
            nameof(BasicContractZeroImplContainer.BasicContractZeroImplStub.ChangeContractDeploymentController);
        var proposalId = await CreateProposalAsync(Tester, contractDeploymentController.ContractAddress,
            contractDeploymentController.OwnerAddress, proposalCreationMethodName,
            new AuthorityInfo
            {
                OwnerAddress = organizationAddress,
                ContractAddress = ParliamentAddress
            });
        await ApproveWithMinersAsync(Tester, ParliamentAddress, proposalId);
        var txResult2 = await ReleaseProposalAsync(Tester, ParliamentAddress, proposalId);
        txResult2.Status.ShouldBe(TransactionResultStatus.Mined);
```
