### Title
Insufficient Validation Allows Malicious Contract to Bypass Method Fee Governance Control

### Summary
The `ChangeMethodFeeController` method in Parliament, Association, Referendum, Genesis, Token, and other system contracts fails to validate that the `ContractAddress` field in the input `AuthorityInfo` points to a legitimate authorization contract. An attacker can exploit this by deploying a malicious contract that always validates organization existence, then gaining governance approval to set this contract as the method fee controller, resulting in permanent direct control over method fees without ongoing governance oversight.

### Finding Description

The vulnerability exists in the `CheckOrganizationExist` method across multiple critical system contracts. This method accepts an `AuthorityInfo` parameter containing a `ContractAddress` field and blindly calls `ValidateOrganizationExist` on that address without verifying it's a legitimate authorization contract (Parliament, Association, or Referendum).

**Affected Locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The validation logic in `ChangeMethodFeeController` only verifies organization existence within the provided contract address: [6](#0-5) 

**Root Cause:**
The code calls `Context.Call<BoolValue>(authorityInfo.ContractAddress, nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value` on any contract address without ensuring it's a system authorization contract. The system has the capability to validate system contracts as shown in other parts of the codebase: [7](#0-6) 

However, this validation is not applied to the `ContractAddress` in `ChangeMethodFeeController`, breaking the security invariant that method fee control must always be through proper governance mechanisms.

### Impact Explanation

**Governance Control Bypass:**
Once an attacker successfully changes the `MethodFeeController` to point to a malicious contract with `OwnerAddress` set to their own address, they gain direct control over method fees for that contract without requiring further governance approval. The `SetMethodFee` method only checks if the sender matches the `OwnerAddress`: [8](#0-7) 

**Critical Impact Scenarios:**
1. **Denial of Service:** Attacker sets method fees to astronomically high values, making it economically infeasible for users to call contract methods
2. **Spam Attacks:** Attacker sets method fees to zero, enabling unlimited free transactions that can flood the network
3. **Targeted Disruption:** Attacker selectively manipulates fees for critical governance methods like `CreateProposal`, `Approve`, `Release`, blocking normal governance operations

**Affected Contracts:**
All system contracts implementing ACS1 are vulnerable, including:
- Parliament (governance coordination)
- Genesis/BasicContractZero (contract deployment and upgrades)
- Token Contract (all token operations)
- Association, Referendum (alternative governance mechanisms)
- Economic, Treasury, Profit, Election, Vote, Configuration, CrossChain, TokenConverter, TokenHolder, and Consensus contracts

**Irreversible Control Loss:**
The attack creates an irreversible state because `ChangeMethodFeeController` requires the sender to match the current `MethodFeeController.Value.OwnerAddress`. When governance proposes to recover control, the transaction executes with a virtual address representing the organization, not the attacker's address, causing the authorization check to fail: [9](#0-8) 

Recovery requires extraordinary measures like emergency contract upgrades, which themselves may be blocked if the attacker manipulates fees for critical upgrade methods.

### Likelihood Explanation

**Attack Preconditions:**
1. Attacker deploys a malicious contract implementing a `ValidateOrganizationExist` method that always returns true
2. Attacker obtains governance approval to change `MethodFeeController` 

**Feasibility Assessment:**
- **Entry Point:** The `ChangeMethodFeeController` method is a public entry point reachable through governance proposals
- **Governance Approval:** While this requires majority support, the proposal can be disguised as legitimate governance restructuring (e.g., "Migrating to new Parliament organization for improved governance")
- **Execution Practicality:** All steps are executable under standard AElf contract semantics - contract deployment and governance proposals are normal operations
- **Economic Rationality:** The cost is minimal (deploying one small contract + normal governance proposal costs), while the impact is catastrophic system-wide control

**Social Engineering Vector:**
The lack of validation makes it easier to mislead governance participants. The malicious contract address could be presented as a new Parliament organization address, and without on-chain validation, participants cannot easily verify its legitimacy.

**Detection Difficulty:**
The test suite confirms that the system only validates organization existence, not contract legitimacy: [10](#0-9) 

### Recommendation

**Immediate Fix:**
Add validation in `CheckOrganizationExist` to ensure the `ContractAddress` is a recognized system authorization contract:

```csharp
private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
{
    // Validate that ContractAddress is a legitimate authorization contract
    var systemContracts = Context.GetSystemContractNameToAddressMapping();
    var isValidAuthContract = 
        authorityInfo.ContractAddress == systemContracts[SmartContractConstants.ParliamentContractSystemHashName] ||
        authorityInfo.ContractAddress == systemContracts[SmartContractConstants.AssociationContractSystemHashName] ||
        authorityInfo.ContractAddress == systemContracts[SmartContractConstants.ReferendumContractSystemHashName];
    
    Assert(isValidAuthContract, "Contract address must be a system authorization contract.");
    
    return Context.Call<BoolValue>(authorityInfo.ContractAddress,
        nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
}
```

**Apply to All Affected Contracts:**
The same fix must be applied to all system contracts using this pattern:
- ParliamentContract_ACS1_TransactionFeeProvider.cs
- AssociationContract_ACS1_TransactionFeeProvider.cs
- ReferendumContract_ACS1_TransactionFeeProvider.cs
- BasicContractZero_Helper.cs
- TokenContract_ACS1_MethodFeeProvider.cs
- And all other ACS1 implementations

**Test Cases:**
Add regression tests to verify rejection of non-authorization contract addresses in `ChangeMethodFeeController` across all affected contracts.

### Proof of Concept

**Step 1: Deploy Malicious Contract**
```csharp
public class MaliciousAuthContract : ContractContainer.ContractBase
{
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = true }; // Always validates
    }
}
```

**Step 2: Create Governance Proposal**
- Target: ParliamentContract.ChangeMethodFeeController
- Parameters: AuthorityInfo { ContractAddress = MaliciousAuthContract, OwnerAddress = AttackerAddress }
- Description: "Upgrading to new governance structure for enhanced security"

**Step 3: Obtain Approval**
- Proposal passes through normal governance (requires majority miner approval)
- Social engineering: Proposal disguised as legitimate governance improvement

**Step 4: Execute Proposal**
- Proposal released and executed
- Validation passes because MaliciousAuthContract.ValidateOrganizationExist returns true
- MethodFeeController.Value = { MaliciousAuthContract, AttackerAddress }

**Step 5: Exploit Direct Control**
- Attacker directly calls SetMethodFee (no proposal needed)
- Sets CreateProposal method fee to 1,000,000 ELF (effectively blocking new proposals)
- Sets Approve method fee to 100,000 ELF (blocking approvals)
- Governance cannot recover because they cannot afford to call ChangeMethodFeeController

**Expected vs Actual:**
- **Expected:** ChangeMethodFeeController should reject non-authorization contract addresses
- **Actual:** Any contract address is accepted if it implements ValidateOrganizationExist returning true

**Success Condition:**
Attacker maintains permanent control over method fees without further governance oversight, while governance cannot recover control through normal mechanisms.

### Citations

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L21-30)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L56-60)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L70-74)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L70-74)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L116-121)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L39-48)
```csharp
    public override Address CreateOrganizationBySystemContract(CreateOrganizationBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to create organization.");
        var organizationAddress = CreateNewOrganization(input.OrganizationCreationInput);
        if (!string.IsNullOrEmpty(input.OrganizationAddressFeedbackMethod))
            Context.SendInline(Context.Sender, input.OrganizationAddressFeedbackMethod, organizationAddress);

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-145)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

        return new Empty();
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L1011-1034)
```csharp
    public async Task ChangeMethodFeeController_With_Invalid_Authority_Test()
    {
        // await InitializeParliamentContracts();
        var parliamentContractStub = GetParliamentContractTester(InitialMinersKeyPairs[0]);


        var methodFeeController = await parliamentContractStub.GetMethodFeeController.CallAsync(new Empty());
        var defaultOrganization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        methodFeeController.OwnerAddress.ShouldBe(defaultOrganization);

        const string proposalCreationMethodName = nameof(parliamentContractStub.ChangeMethodFeeController);
        var proposalId = await CreateFeeProposalAsync(ParliamentContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName, new AuthorityInfo
            {
                OwnerAddress = ParliamentContractAddress,
                ContractAddress = ParliamentContractAddress
            });
        await ApproveAsync(InitialMinersKeyPairs[0], proposalId);
        await ApproveAsync(InitialMinersKeyPairs[1], proposalId);
        await ApproveAsync(InitialMinersKeyPairs[2], proposalId);

        var releaseResult = await parliamentContractStub.Release.SendWithExceptionAsync(proposalId);
        releaseResult.TransactionResult.Error.ShouldContain("Invalid authority input");
    }
```
