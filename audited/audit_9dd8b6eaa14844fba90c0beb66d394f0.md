### Title
Permanent Method Fee Controller Lock-Out Due to Irreversible Controller Change Without Recovery Mechanism

### Summary
The `RequiredMethodFeeControllerSet()` function contains an early return that prevents the method fee controller from being reinitialized to the default Parliament organization once changed. If the controller is changed to a custom organization that later becomes non-functional (e.g., all members lose access to their keys), the method fee configuration becomes permanently frozen with no recovery path.

### Finding Description

The vulnerability exists in the `RequiredMethodFeeControllerSet()` private method: [1](#0-0) 

The early return at line 52 ensures that once `State.MethodFeeController.Value` is set, the function never reinitializes it back to the default Parliament organization. While the `ChangeMethodFeeController` function exists to change the controller: [2](#0-1) 

This function requires authorization from the **current** controller's owner address (line 25). When a proposal is released by a governance organization, the transaction executes from the organization's virtual address: [3](#0-2) 

The authorization check in `ChangeMethodFeeController` validates that `Context.Sender` equals the controller's `OwnerAddress`, which is the organization's virtual address. If that organization becomes non-functional (all members lose keys, members become unavailable, organization set to defunct state), no entity can authorize a proposal to change the controller back.

The `CheckOrganizationExist` validation only verifies that an organization address exists in state, not that it remains functional: [4](#0-3) [5](#0-4) 

Organizations persist in state indefinitely once created and cannot be deleted, so they always "exist" even if non-functional. Test cases confirm that invalid organizations are rejected during controller changes: [6](#0-5) 

However, there is no mechanism to handle organizations that exist but cannot function (e.g., impossible quorum due to lost keys).

### Impact Explanation

**Operational Impact - Permanent DoS of Method Fee Configuration:**
- Method fees for the Economic contract become permanently frozen and cannot be updated
- Existing fees continue to function, but any necessary adjustments (e.g., during market changes, fee optimization, emergency situations) become impossible
- The entire method fee governance capability for the Economic contract is permanently bricked
- This affects the economic model's ability to adapt to changing conditions

**Affected Parties:**
- Chain operators who cannot adjust economic parameters
- Users who may be stuck with suboptimal fee structures
- Protocol governance which loses a critical configuration lever

**Severity Justification:**
This is a **Medium** severity operational impact. While it does not directly result in fund theft or inflation, it causes permanent loss of a critical governance capability. The inability to adjust method fees could have cascading economic effects on the protocol over time.

### Likelihood Explanation

**Realistic Exploitability:**

**Preconditions:**
1. Parliament default organization (2/3+ miners) approves a proposal to change the method fee controller to a custom organization (e.g., specialized fee management Association)
2. The custom organization later becomes non-functional due to:
   - All members losing access to their private keys
   - Members becoming permanently unavailable
   - Deliberate compromise where attacker-controlled Parliament sets a defunct controller

**Feasibility:**
- **Legitimate scenario**: Governance delegates fee management to a specialized multi-sig organization for operational efficiency, but key management practices fail
- **Attack scenario**: Compromised Parliament (already requires 2/3 miner compromise) deliberately sets controller to an unusable organization to brick fee configuration
- **Execution practicality**: High - only requires Parliament proposal approval, no complex exploit chain

**Probability Assessment:**
Medium likelihood. While it requires a governance decision to change the controller and subsequent key management failure, both are plausible:
- Delegating to specialized organizations is common practice
- Key loss/unavailability in multi-sig setups is a documented real-world problem
- No automated safeguards or recovery mechanisms exist

### Recommendation

**Code-Level Mitigation:**

Add an emergency recovery mechanism that allows the Parliament default organization to reset the controller even when already set. Modify `EconomicContract_ACS1_TransactionFeeProvider.cs`:

```csharp
public override Empty ResetMethodFeeControllerToDefault(Empty input)
{
    // Get Parliament default organization
    if (State.ParliamentContract.Value == null)
        State.ParliamentContract.Value = 
            Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    
    var defaultParliamentOrg = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
    Assert(Context.Sender == defaultParliamentOrg, "Only Parliament default organization can reset controller.");
    
    // Reset to default
    State.MethodFeeController.Value = new AuthorityInfo
    {
        OwnerAddress = defaultParliamentOrg,
        ContractAddress = State.ParliamentContract.Value
    };
    
    return new Empty();
}
```

**Alternative/Additional Protections:**

1. **Enhanced Validation**: Before allowing controller change, verify the new organization can actually authorize transactions (test proposal creation/approval)

2. **Timeout Mechanism**: Add a "last successful operation" timestamp and allow reset to default if controller hasn't authorized any changes within a defined period

3. **Secondary Recovery Authority**: Implement a high-threshold emergency response organization that can reset the controller

**Test Cases to Add:**
1. Test controller change to custom organization followed by simulated key loss (inability to authorize)
2. Test recovery via emergency reset mechanism
3. Test that only authorized entities can trigger recovery
4. Test that recovery properly restores default Parliament control

### Proof of Concept

**Initial State:**
- Economic contract deployed and initialized
- Method fee controller set to Parliament default organization (default behavior)

**Exploitation Steps:**

1. **Parliament approves controller delegation:**
   - Create Association organization with 3 specific members
   - Create Parliament proposal to call `ChangeMethodFeeController` with new Association organization
   - Miners approve and release proposal
   - Controller now points to custom Association organization

2. **Organization becomes non-functional:**
   - All 3 Association members lose access to their private keys (simulated by losing key material)
   - OR members become permanently unavailable

3. **Attempt recovery (fails):**
   - Try to create proposal in Association to change controller back → **FAILS**: No member can sign
   - Try to create new Parliament proposal to change controller → **FAILS**: `ChangeMethodFeeController` requires `Context.Sender == Association.OwnerAddress`, but Parliament's sender is Parliament organization, not Association
   - Try to call `ChangeMethodFeeController` directly → **FAILS**: Requires sender to be Association organization address

4. **Verify permanent lock:**
   - `GetMethodFeeController` returns the defunct Association organization
   - `SetMethodFee` requires Association organization as sender → **Cannot execute**
   - `ChangeMethodFeeController` requires Association organization as sender → **Cannot execute**
   - No function exists to reset controller to default

**Expected vs Actual Result:**
- **Expected**: Should have recovery path to restore Parliament default organization control
- **Actual**: Method fee configuration permanently frozen with no recovery mechanism

**Success Condition:**
The vulnerability is confirmed if, after controller change to a custom organization that becomes non-functional, there exists no transaction sequence that can restore control or modify method fees.

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L22-31)
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

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L50-64)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs (L71-76)
```csharp
    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.ValidateOrganizationExist),
            authorityInfo.OwnerAddress).Value;
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L281-284)
```csharp
    public override BoolValue ValidateOrganizationExist(Address input)
    {
        return new BoolValue { Value = State.Organizations[input] != null };
    }
```

**File:** test/AElf.Contracts.CrossChain.Tests/SideChainLifeTimeManagementTest.cs (L67-89)
```csharp
    public async Task ChangeIndexingController_InvalidOwnerAddress()
    {
        await InitializeCrossChainContractAsync();
        var oldOrganizationAddress =
            (await CrossChainContractStub.GetCrossChainIndexingController.CallAsync(new Empty())).OwnerAddress;
        var proposalRes = await ParliamentContractStub.CreateProposal.SendAsync(new CreateProposalInput
        {
            ContractMethodName = nameof(CrossChainContractStub.ChangeCrossChainIndexingController),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            Params = new AuthorityInfo
            {
                ContractAddress = ParliamentContractAddress, OwnerAddress = DefaultSender
            }.ToByteString(),
            ToAddress = CrossChainContractAddress,
            OrganizationAddress = oldOrganizationAddress
        });

        var proposalId = Hash.Parser.ParseFrom(proposalRes.TransactionResult.ReturnValue);
        await ApproveWithMinersAsync(proposalId);
        var releaseResult = (await ParliamentContractStub.Release.SendWithExceptionAsync(proposalId))
            .TransactionResult;
        releaseResult.Error.ShouldContain("Invalid authority input.");
    }
```
