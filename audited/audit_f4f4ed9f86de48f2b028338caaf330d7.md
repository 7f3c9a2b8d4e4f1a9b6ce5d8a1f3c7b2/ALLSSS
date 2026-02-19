### Title
Insufficient Address Validation in Governance Proposal Creation Allows Zero Address Proposals

### Summary
The Association, Parliament, and Referendum contracts validate proposal ToAddress using only null reference checks (`ToAddress == null`), which does not detect Address objects with empty ByteString values. This allows creation of invalid proposals targeting zero addresses that pass validation but will always fail upon release execution, wasting governance resources and enabling potential DoS attacks on the governance system.

### Finding Description

The vulnerability exists in the `Validate(ProposalInfo proposal)` method across all three governance contracts:

**Association Contract:** [1](#0-0) 

The validation only checks `proposal.ToAddress == null`, which catches null references but not Address objects with empty ByteString values.

**Parliament Contract:** [2](#0-1) 

**Referendum Contract:** [3](#0-2) 

All three contracts use the same insufficient pattern: `proposal.ToAddress != null`.

**Root Cause:**
In AElf, an Address is a protobuf message with a `Value` property of type `ByteString`. An attacker can create an Address object using `new Address()` which has a non-null reference but an empty ByteString value. The current validation only checks the reference, not the content. [4](#0-3) 

**Correct Validation Pattern:**
The codebase demonstrates the proper validation pattern in multiple locations: [5](#0-4) [6](#0-5) 

Both correctly check: `input != null && !input.Value.IsNullOrEmpty()`.

**Execution Flow:**
When a proposal with an empty ToAddress is released: [7](#0-6) 

The `SendVirtualInlineBySystemContract` creates an inline transaction with the empty address: [8](#0-7) 

During execution, `GetExecutiveAsync` only validates null references: [9](#0-8) 

The lookup fails at the Genesis contract level, throwing `SmartContractFindRegistrationException`, which is caught: [10](#0-9) 

The transaction fails with "Invalid contract address" error, but only AFTER the proposal has consumed governance resources.

### Impact Explanation

**Operational Impact - Governance DoS:**
- Whitelisted proposers can create invalid proposals that pass all validation checks
- Organization members waste time reviewing and voting on proposals that will never execute successfully
- Each invalid proposal consumes gas for creation, voting transactions, and failed release attempts
- The governance queue becomes clogged with invalid proposals, delaying legitimate governance actions
- Proposals remain in storage until expiration, consuming state space

**Who is Affected:**
- All organization members who participate in voting
- The organization itself through wasted resources and delayed legitimate proposals
- The broader ecosystem if critical governance actions are delayed

**Severity Justification:**
While this vulnerability does not lead to fund theft or unauthorized execution, it represents a significant operational risk to the governance system. An attacker with proposer whitelist access can systematically create invalid proposals, forcing the organization to:
1. Spend gas reviewing and voting on each proposal
2. Wait for approval thresholds to be met
3. Attempt release (consuming more gas)
4. Only then discover the proposal is invalid

The vulnerability violates the invariant that "proposal lifetime/expiration" checks should ensure only valid proposals consume governance resources. Invalid proposals should be rejected at creation time, not execution time.

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is accessible through public methods:
- `CreateProposal` / `CreateProposalBySystemContract` in Association
- Equivalent methods in Parliament and Referendum [11](#0-10) 

**Attacker Capabilities:**
- Requires being in the organization's proposer whitelist (by design)
- No additional privileges needed
- Can be executed repeatedly

**Attack Complexity:**
Trivial - simply pass `new Address()` or construct an Address with empty ByteString as the `ToAddress` in `CreateProposalInput`.

**Feasibility:**
Highly feasible and deterministic:
1. Attacker is added to proposer whitelist (legitimate step)
2. Creates proposal with `ToAddress = new Address()`
3. Validation passes (checks only null reference)
4. Proposal is stored and votable
5. Upon release, execution fails with "Invalid contract address"

**Detection:**
Currently difficult to detect before voting completes, as the proposal appears valid until release is attempted.

### Recommendation

**Code-Level Mitigation:**
Update all three governance contracts to use comprehensive address validation:

```csharp
private bool Validate(ProposalInfo proposal)
{
    if (proposal.ToAddress == null || proposal.ToAddress.Value.IsNullOrEmpty() || 
        string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

**Files to Update:**
1. `contract/AElf.Contracts.Association/Association_Helper.cs` line 85
2. `contract/AElf.Contracts.Parliament/Parliament_Helper.cs` line 159
3. `contract/AElf.Contracts.Referendum/Referendum_Helper.cs` line 106

**Invariant Checks:**
Add explicit assertion helper:
```csharp
private void AssertValidProposalAddress(Address address)
{
    Assert(address != null && !address.Value.IsNullOrEmpty(), "Invalid proposal target address.");
}
```

**Test Cases:**
Add regression tests for each governance contract:
1. Test proposal creation with `new Address()` - should fail with "Invalid proposal"
2. Test proposal creation with Address containing empty ByteString - should fail
3. Test proposal creation with valid address - should succeed

### Proof of Concept

**Initial State:**
- User is in organization's proposer whitelist
- Organization is properly configured with valid thresholds and members

**Attack Steps:**

1. Create proposal input with empty address:
```csharp
var maliciousProposal = new CreateProposalInput
{
    OrganizationAddress = validOrganizationAddress,
    ContractMethodName = "SomeMethod",
    ToAddress = new Address(), // Empty ByteString value
    Params = ByteString.Empty,
    ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
};
```

2. Call `CreateProposal`:
    - Transaction succeeds
    - Proposal is created and stored
    - ProposalId is returned

3. Organization members vote and approve the proposal

4. Proposer calls `Release(proposalId)`:
    - Inline transaction is created with empty ToAddress
    - Execution attempts to get executive for empty address
    - `GetExecutiveAsync` fails to find contract registration
    - Transaction fails with "Invalid contract address"
    - Gas consumed, proposal was invalid from the start

**Expected Result:**
Proposal creation should fail immediately with validation error.

**Actual Result:**
Proposal creation succeeds, consuming governance resources before failing at execution time.

**Success Condition:**
The attack succeeds when the invalid proposal is created and stored, demonstrating the validation bypass.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L83-90)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
            !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
            return false;

        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L157-166)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = CheckProposalNotExpired(proposal);
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L104-113)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** src/AElf.Types/Extensions/ByteStringExtensions.cs (L34-37)
```csharp
        public static bool IsNullOrEmpty(this ByteString byteString)
        {
            return byteString == null || byteString.IsEmpty;
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L537-544)
```csharp
    public override Empty SetSigner(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input.");

        if (State.SignerMap[Context.Sender] == input) return new Empty();

        State.SignerMap[Context.Sender] = input;
        return new Empty();
```

**File:** contract/AElf.Contracts.Association/Association.cs (L107-121)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
    }

    public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Not authorized to propose.");
        AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);
        var proposalId = CreateNewProposal(input.ProposalInput);
        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-201)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);

        Context.Fire(new ProposalReleased
        {
            ProposalId = input,
            OrganizationAddress = proposalInfo.OrganizationAddress
        });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L278-291)
```csharp
    public void SendVirtualInlineBySystemContract(Hash fromVirtualAddress, Address toAddress, string methodName,
        ByteString args, bool logTransaction)
    {
        var transaction = new Transaction
        {
            From = ConvertVirtualAddressToContractAddressWithContractHashName(fromVirtualAddress, Self),
            To = toAddress,
            MethodName = methodName,
            Params = args
        };
        TransactionContext.Trace.InlineTransactions.Add(transaction);
        if (!logTransaction) return;
        FireVirtualTransactionLogEvent(fromVirtualAddress, transaction);
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractExecutiveService.cs (L45-63)
```csharp
    public async Task<IExecutive> GetExecutiveAsync(IChainContext chainContext, Address address)
    {
        if (address == null) throw new ArgumentNullException(nameof(address));

        var pool = _smartContractExecutiveProvider.GetPool(address);
        var smartContractRegistration = await GetSmartContractRegistrationAsync(chainContext, address);

        if (!pool.TryTake(out var executive))
        {
            executive = await GetExecutiveAsync(smartContractRegistration);
        }
        else if (smartContractRegistration.CodeHash != executive.ContractHash)
        {
            _smartContractExecutiveProvider.TryRemove(address, out _);
            executive = await GetExecutiveAsync(smartContractRegistration);
        }

        return executive;
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L156-161)
```csharp
        catch (SmartContractFindRegistrationException)
        {
            txContext.Trace.ExecutionStatus = ExecutionStatus.ContractError;
            txContext.Trace.Error += "Invalid contract address.\n";
            return trace;
        }
```
