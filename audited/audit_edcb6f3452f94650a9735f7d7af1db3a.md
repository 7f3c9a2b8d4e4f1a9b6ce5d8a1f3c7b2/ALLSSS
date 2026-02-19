### Title
Malicious Authorization Contract Bypass in Side Chain Controller Changes

### Summary
The `ChangeSideChainLifetimeController` and `ChangeSideChainIndexingFeeController` methods use `ValidateAuthorityInfoExists` which allows arbitrary contract addresses without validation against legitimate authorization contracts (Parliament, Association, Referendum). An attacker controlling the current controller can set a malicious contract that bypasses all governance checks, enabling unauthorized side chain creation and management without proper approval.

### Finding Description

The vulnerability exists in two controller change methods that fail to validate the `ContractAddress` field of the input `AuthorityInfo`: [1](#0-0) [2](#0-1) 

Both methods rely on `ValidateAuthorityInfoExists` which calls `ValidateOrganizationExist` on the user-provided `ContractAddress`: [3](#0-2) 

**Root Cause:** There is no whitelist validation ensuring the `ContractAddress` is a legitimate system authorization contract. A malicious contract can implement `ValidateOrganizationExist` to always return `true` for any address.

**Why Protections Fail:** The authorization checks (`AssertSideChainLifetimeControllerAuthority` and `authorityInfo.OwnerAddress == Context.Sender`) only verify the caller controls the *current* controller, but don't prevent changing to a malicious contract. Once set, this malicious contract receives system contract privileges when called.

**Execution Path:** The malicious contract is invoked in critical operations: [4](#0-3) [5](#0-4) 

Legitimate authorization contracts verify the caller is a system contract: [6](#0-5) 

A malicious contract can omit this check and auto-approve all proposals without governance.

**Contrast with Secure Implementation:** The `ChangeCrossChainIndexingController` method correctly restricts to Parliament contract only: [7](#0-6) 

### Impact Explanation

**Governance Bypass:** An attacker controlling the current controller organization (through legitimate voting or compromise) can permanently escalate privileges by setting a malicious contract. This breaks the fundamental governance invariant that each action requires ongoing organizational approval.

**Concrete Harms:**
1. **Unauthorized Side Chain Creation:** The malicious contract can auto-approve all `CreateSideChain` proposals without real governance votes, enabling unlimited side chain creation
2. **Resource Exhaustion:** Attackers can create arbitrary side chains, depleting network resources and token reserves
3. **Trust Model Violation:** The system design requires proposal approval for each action; this bypass allows permanent ungoverned control
4. **Operational Integrity Loss:** Future legitimate governance participants lose control over side chain lifecycle management

**Affected Parties:** All network participants, parent chain validators, and legitimate side chain creators who rely on proper governance enforcement.

**Severity Justification:** High - Complete governance bypass for critical cross-chain operations, enabling unauthorized state modifications and resource allocation.

### Likelihood Explanation

**Attacker Capabilities:** Requires initial control of current controller organization (achievable through legitimate voting, social engineering, or if organization has few members).

**Attack Complexity:** 
1. Deploy malicious contract with `ValidateOrganizationExist` returning `true` and `CreateProposalBySystemContract`/`Release` methods bypassing checks
2. Gain control of current controller organization through legitimate means
3. Call `ChangeSideChainLifetimeController` with malicious `AuthorityInfo`
4. Execute ungoverned operations through malicious contract

**Feasibility:** Highly feasible - requires only standard contract deployment and one controller-authorized transaction. The test suite demonstrates the system accepts Association contracts, confirming no contract type restrictions: [8](#0-7) 

**Economic Rationality:** The cost of deploying a malicious contract and executing the attack is minimal compared to the value of controlling side chain creation and management.

**Detection:** Difficult - the controller change appears legitimate on-chain; only off-chain analysis of the new contract code would reveal malicious intent.

### Recommendation

**Immediate Fix:** Add contract address whitelist validation similar to `ChangeCrossChainIndexingController`:

```csharp
public override Empty ChangeSideChainLifetimeController(AuthorityInfo input)
{
    AssertSideChainLifetimeControllerAuthority(Context.Sender);
    
    // Add whitelist check
    SetContractStateRequired(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
    SetContractStateRequired(State.AssociationContract, SmartContractConstants.AssociationContractSystemName);
    SetContractStateRequired(State.ReferendumContract, SmartContractConstants.ReferendumContractSystemName);
    
    Assert(
        input.ContractAddress == State.ParliamentContract.Value ||
        input.ContractAddress == State.AssociationContract.Value ||
        input.ContractAddress == State.ReferendumContract.Value,
        "ContractAddress must be a system authorization contract.");
    
    Assert(ValidateAuthorityInfoExists(input), "Invalid authority input.");
    State.SideChainLifetimeController.Value = input;
    // ... rest of method
}
```

Apply the same fix to `ChangeSideChainIndexingFeeController`.

**Invariant to Enforce:** Controller `ContractAddress` must always be one of the three legitimate system authorization contracts: Parliament, Association, or Referendum.

**Test Cases:**
1. Attempt to set controller with arbitrary contract address - should fail
2. Attempt to set controller with legitimate contract but invalid organization - should fail  
3. Successfully set controller with Parliament/Association/Referendum and valid organization
4. Verify malicious contract cannot be used after fix

### Proof of Concept

**Initial State:**
- CrossChain contract deployed with default Parliament controller
- Attacker controls majority of parliament members (or association organization members)

**Attack Steps:**

1. **Deploy Malicious Contract:**
```csharp
// MaliciousAuthContract.cs
public override BoolValue ValidateOrganizationExist(Address input)
{
    return new BoolValue { Value = true }; // Always returns true
}

public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
{
    // Skip authorization check, auto-approve
    var proposalId = HashHelper.ComputeFrom(input);
    // Store as pre-approved
    return proposalId;
}

public override Empty Release(Hash input)
{
    // Always succeeds without real voting
    return new Empty();
}
```

2. **Change Controller (via legitimate governance vote):**
```csharp
await CrossChainContractStub.ChangeSideChainLifetimeController.SendAsync(
    new AuthorityInfo {
        ContractAddress = maliciousContractAddress,
        OwnerAddress = attackerAddress
    });
```

3. **Bypass Governance:**
```csharp
// Now attacker can create side chains without approval
await CrossChainContractStub.RequestSideChainCreation.SendAsync(request);
await CrossChainContractStub.ReleaseSideChainCreation.SendAsync(proposalId);
// Side chain created without real governance votes
```

**Expected Result:** Transaction should fail with "ContractAddress must be a system authorization contract"

**Actual Result:** Malicious contract accepted, enabling ungoverned side chain operations

**Success Condition:** Attack succeeds when side chain is created without legitimate organizational approval through the malicious contract.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L61-74)
```csharp
    public override Empty ChangeCrossChainIndexingController(AuthorityInfo input)
    {
        AssertCrossChainIndexingControllerAuthority(Context.Sender);
        SetContractStateRequired(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
        Assert(
            input.ContractAddress == State.ParliamentContract.Value &&
            ValidateParliamentOrganization(input.OwnerAddress), "Invalid authority input.");
        State.CrossChainIndexingController.Value = input;
        Context.Fire(new CrossChainIndexingControllerChanged
        {
            AuthorityInfo = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L76-86)
```csharp
    public override Empty ChangeSideChainLifetimeController(AuthorityInfo input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);
        Assert(ValidateAuthorityInfoExists(input), "Invalid authority input.");
        State.SideChainLifetimeController.Value = input;
        Context.Fire(new SideChainLifetimeControllerChanged
        {
            AuthorityInfo = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L108-110)
```csharp
            Context.SendInline(State.SideChainLifetimeController.Value.ContractAddress,
                nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release),
                input.ProposalId);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L257-271)
```csharp
    public override Empty ChangeSideChainIndexingFeeController(ChangeSideChainIndexingFeeControllerInput input)
    {
        var sideChainInfo = State.SideChainInfo[input.ChainId];
        var authorityInfo = sideChainInfo.IndexingFeeController;
        Assert(authorityInfo.OwnerAddress == Context.Sender, "No permission.");
        Assert(ValidateAuthorityInfoExists(input.AuthorityInfo), "Invalid authority input.");
        sideChainInfo.IndexingFeeController = input.AuthorityInfo;
        State.SideChainInfo[input.ChainId] = sideChainInfo;
        Context.Fire(new SideChainIndexingFeeControllerChanged
        {
            ChainId = input.ChainId,
            AuthorityInfo = input.AuthorityInfo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L378-380)
```csharp
        Context.SendInline(sideChainLifeTimeController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L676-681)
```csharp
    private bool ValidateAuthorityInfoExists(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L68-76)
```csharp
    public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to propose.");
        AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);

        var proposalId = CreateNewProposal(input.ProposalInput);
        return proposalId;
    }
```

**File:** test/AElf.Contracts.CrossChain.Tests/SideChainLifeTimeManagementTest.cs (L578-583)
```csharp
                AuthorityInfo = new AuthorityInfo
                {
                    ContractAddress = AssociationContractAddress,
                    OwnerAddress = newSideChainFeeControllerAddress
                }
            });
```
