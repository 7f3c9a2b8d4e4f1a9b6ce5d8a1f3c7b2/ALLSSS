# Audit Report

## Title
Empty Whitelist DOS: User Contract Deployment Blocked on Non-Public Side Chains

## Summary
The `AssertUserDeployContract()` function implements incomplete authorization logic that blocks all user contract deployments on non-public side chains when the Parliament proposer whitelist is legitimately empty. The function only checks whitelist membership but fails to verify parliament membership when `ParliamentMemberProposingAllowed` is enabled, causing a complete DOS of contract deployment functionality even for authorized miners.

## Finding Description

The vulnerability exists in the authorization check for user contract deployment on side chains. The `DeployUserSmartContract()` method is the sole entry point for deploying user contracts. [1](#0-0) 

On non-public side chains (where `NativeSymbol != PrimaryTokenSymbol`), this method invokes `AssertUserDeployContract()` which only validates that the sender is present in the Parliament's global proposer whitelist. [2](#0-1) 

The Parliament contract explicitly permits empty whitelists when `ParliamentMemberProposingAllowed` is true, as shown in the `ChangeOrganizationProposerWhiteList()` validation. [3](#0-2) 

The default Parliament organization is always created with `ParliamentMemberProposingAllowed = true`. [4](#0-3) 

The correct authorization pattern is implemented in the Parliament contract's `AssertIsAuthorizedProposer()` method, which checks three conditions: authority check disabled, sender in whitelist, OR sender is a parliament member when member proposing is allowed. [5](#0-4) 

However, `AssertUserDeployContract()` only checks the whitelist and ignores the parliament membership condition, creating an inconsistency. When the whitelist is empty (a valid state), the assertion always fails with "No permission," blocking all deployment attempts including those from authorized parliament members.

The whitelist can legitimately become empty during Parliament initialization when `PrivilegedProposer` is null. [6](#0-5) 

Test evidence confirms this limitation: all side chain user contract deployment tests first call `AddZeroContractToProposerWhiteListAsync()` to add addresses to the whitelist, working around the incomplete authorization check. [7](#0-6) 

## Impact Explanation

**Complete Protocol DOS:**
- All user contract deployments permanently fail on affected side chains
- Authorized parliament members (miners) who should be able to deploy when `ParliamentMemberProposingAllowed = true` are blocked
- No alternative deployment path exists
- Entire side chain ecosystem loses the ability to add new user contracts

**Affected Infrastructure:**
- Non-public side chains where `NativeSymbol != PrimaryTokenSymbol` (standard side chain configuration)
- Any side chain with an empty Parliament proposer whitelist combined with `ParliamentMemberProposingAllowed = true` (explicitly allowed state)

**Severity: HIGH** - Complete failure of critical protocol functionality with no bypass mechanism.

## Likelihood Explanation

**Legitimate Preconditions:**
1. Non-public side chain configuration (common for most side chains)
2. Empty Parliament proposer whitelist (explicitly permitted when `ParliamentMemberProposingAllowed = true`)

**No Attack Required:**
The vulnerability manifests from valid operational state:
- Normal governance via `ChangeOrganizationProposerWhiteList` can clear the whitelist
- Initial deployment with null `PrivilegedProposer` creates empty whitelist automatically

**Test Evidence:**
The test suite explicitly works around this issue by populating the whitelist before every user contract deployment on side chains, confirming developers are aware of the limitation but have not fixed the production code.

**Probability: HIGH** - Occurs in legitimate operational configurations on side chains.

## Recommendation

Modify `AssertUserDeployContract()` to implement the same three-condition authorization logic used in Parliament's `AssertIsAuthorizedProposer()`:

```csharp
private void AssertUserDeployContract()
{
    RequireTokenContractContractAddressSet();
    var primaryTokenSymbol = State.TokenContract.GetPrimaryTokenSymbol.Call(new Empty()).Value;
    if (Context.Variables.NativeSymbol == primaryTokenSymbol)
    {
        return;
    }

    RequireParliamentContractAddressSet();
    var defaultOrg = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
    var organization = State.ParliamentContract.GetOrganization.Call(defaultOrg);
    var whitelist = State.ParliamentContract.GetProposerWhiteList.Call(new Empty());
    
    // Check: authority not required OR in whitelist OR (member proposing allowed AND is member)
    var isAuthorized = !organization.ProposerAuthorityRequired ||
                       whitelist.Proposers.Contains(Context.Sender) ||
                       (organization.ParliamentMemberProposingAllowed && 
                        State.ParliamentContract.ValidateAddressIsParliamentMember.Call(Context.Sender).Value);
    
    Assert(isAuthorized, "No permission.");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DeployUserSmartContract_EmptyWhitelist_ParliamentMember_Should_Fail()
{
    // Setup side chain with empty whitelist
    StartSideChain("ELF");
    
    // Verify whitelist is empty
    var whitelist = await SideChainTester.CallContractMethodAsync(
        SideParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.GetProposerWhiteList),
        new Empty());
    var proposerWhiteList = ProposerWhiteList.Parser.ParseFrom(whitelist);
    proposerWhiteList.Proposers.Count.ShouldBe(0);
    
    // Verify ParliamentMemberProposingAllowed is true
    var defaultOrg = await SideChainTester.CallContractMethodAsync(
        SideParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.GetDefaultOrganizationAddress),
        new Empty());
    var orgAddress = Address.Parser.ParseFrom(defaultOrg);
    var orgBytes = await SideChainTester.CallContractMethodAsync(
        SideParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.GetOrganization),
        orgAddress);
    var organization = Organization.Parser.ParseFrom(orgBytes);
    organization.ParliamentMemberProposingAllowed.ShouldBeTrue();
    
    // Verify sender is a parliament member
    var isMember = await SideChainTester.CallContractMethodAsync(
        SideParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.ValidateAddressIsParliamentMember),
        SideChainTester.GetCallOwnerAddress());
    var memberCheck = BoolValue.Parser.ParseFrom(isMember);
    memberCheck.Value.ShouldBeTrue();
    
    // Attempt to deploy user contract - should succeed but will fail
    var contractDeploymentInput = new ContractDeploymentInput
    {
        Category = KernelConstants.DefaultRunnerCategory,
        Code = ByteString.CopyFrom(Codes.Single(kv => kv.Key.Contains("TokenConverter")).Value)
    };
    
    var deployResult = await SideChainTester.ExecuteContractWithMiningAsync(
        SideBasicContractZeroAddress,
        nameof(ACS0Container.ACS0Stub.DeployUserSmartContract),
        contractDeploymentInput);
    
    // BUG: Deployment fails with "No permission" even though sender is parliament member
    deployResult.Status.ShouldBe(TransactionResultStatus.Failed);
    deployResult.Error.ShouldContain("No permission.");
}
```

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L409-412)
```csharp
    public override DeployUserSmartContractOutput DeployUserSmartContract(UserContractDeploymentInput input)
    {
        AssertInlineDeployOrUpdateUserContract();
        AssertUserDeployContract();
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L344-357)
```csharp
    private void AssertUserDeployContract()
    {
        // Only the symbol of main chain or public side chain is native symbol.
        RequireTokenContractContractAddressSet();
        var primaryTokenSymbol = State.TokenContract.GetPrimaryTokenSymbol.Call(new Empty()).Value;
        if (Context.Variables.NativeSymbol == primaryTokenSymbol)
        {
            return;
        }

        RequireParliamentContractAddressSet();
        var whitelist = State.ParliamentContract.GetProposerWhiteList.Call(new Empty());
        Assert(whitelist.Proposers.Contains(Context.Sender), "No permission.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L11-21)
```csharp
    public override Empty Initialize(InitializeInput input)
    {
        Assert(!State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;

        var proposerWhiteList = new ProposerWhiteList();

        if (input.PrivilegedProposer != null)
            proposerWhiteList.Proposers.Add(input.PrivilegedProposer);

        State.ProposerWhiteList.Value = proposerWhiteList;
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L22-34)
```csharp
        var organizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = DefaultOrganizationMinimalApprovalThreshold,
                MinimalVoteThreshold = DefaultOrganizationMinimalVoteThresholdThreshold,
                MaximalAbstentionThreshold = DefaultOrganizationMaximalAbstentionThreshold,
                MaximalRejectionThreshold = DefaultOrganizationMaximalRejectionThreshold
            },
            ProposerAuthorityRequired = input.ProposerAuthorityRequired,
            ParliamentMemberProposingAllowed = true
        };
        var defaultOrganizationAddress = CreateNewOrganization(organizationInput);
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L162-177)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var defaultOrganizationAddress = State.DefaultOrganizationAddress.Value;
        Assert(defaultOrganizationAddress == Context.Sender, "No permission.");
        var organization = State.Organizations[defaultOrganizationAddress];
        Assert(
            input.Proposers.Count > 0 || !organization.ProposerAuthorityRequired ||
            organization.ParliamentMemberProposingAllowed, "White list can't be empty.");
        State.ProposerWhiteList.Value = input;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
    }
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

**File:** test/AElf.Contracts.Genesis.Tests/GenesisContractAuthTest.cs (L1874-1906)
```csharp
    private async Task AddZeroContractToProposerWhiteListAsync()
    {
        var result = await SideChainTester.CallContractMethodAsync(
            SideParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.GetDefaultOrganizationAddress),
            new Empty());
        var organizationAddress = Address.Parser.ParseFrom(result);
        
        var proposerWhiteList = new ProposerWhiteList
        {
            Proposers = { SideBasicContractZeroAddress, SideChainTester.GetCallOwnerAddress() }
        };
        
        var createProposalInput = new CreateProposalInput
        {
            ContractMethodName = nameof(ParliamentContractImplContainer.ParliamentContractImplStub
                .ChangeOrganizationProposerWhiteList),
            ToAddress = SideParliamentAddress,
            Params = proposerWhiteList.ToByteString(),
            ExpiredTime = DateTime.UtcNow.AddDays(1).ToTimestamp(),
            OrganizationAddress = organizationAddress
        };
        
        var createResult = await SideChainTester.ExecuteContractWithMiningAsync(SideParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateProposal),
            createProposalInput);
        var proposalId = Hash.Parser.ParseFrom(createResult.ReturnValue);
        
        await ApproveWithMinersAsync(SideChainTester, SideParliamentAddress, proposalId);

        await SideChainTester.ExecuteContractWithMiningAsync(SideParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.Release), proposalId);
    }
```
