### Title
Permanent DoS of Side Chain Dividend Pool Operations Due to Unrecoverable TokenHolderContract Initialization Failure

### Summary
The `InitialProfitSchemeForSideChain()` function performs an early return if the TokenHolderContract is not deployed, leaving `State.TokenHolderContract.Value` uninitialized. Since the initialization method can only be called once, this creates a permanent DoS condition where public dividend pool methods (`Donate`, `GetSymbolList`, `GetUndistributedDividends`) will fail with null reference errors whenever invoked, with no recovery mechanism available.

### Finding Description

The vulnerability exists in the consensus contract initialization flow for side chains: [1](#0-0) 

The initialization function checks if TokenHolderContract is deployed. If null, it logs and returns early (lines 21-25) without setting `State.TokenHolderContract.Value`. 

The parent initialization method can only execute once: [2](#0-1) 

The initialization check at line 24 enforces single execution via assertion. Once `State.Initialized.Value` is set to true (line 25), reinitializat is permanently blocked.

**Root Cause:** No lazy initialization pattern exists for TokenHolderContract (unlike other contracts): [3](#0-2) 

Other contracts use "Ensure*AddressSet()" helper methods that perform lazy initialization, but no such method exists for TokenHolderContract. [4](#0-3) 

**Why Protections Fail:** Multiple public methods depend on the initialized contract reference but lack null checks:

1. **Donate() method** - Uses TokenHolderContract without null check: [5](#0-4) 

At line 56, `State.TokenHolderContract.Value` is used as the spender (will be null). At line 59, calling `Send()` on a null contract reference will fail: [6](#0-5) 

The `Send()` method accesses `_parent.Value` (line 20) which will be null, causing `Context.SendInline()` to fail.

2. **GetSymbolList() and GetUndistributedDividends()** - Both call `GetSideChainDividendPoolScheme()`: [7](#0-6) [8](#0-7) 

Line 167 calls `State.TokenHolderContract.GetScheme.Call()` on null reference, causing failure.

Only the `Release()` method has proper null handling: [9](#0-8) 

### Impact Explanation

**Operational Impact - Permanent DoS:**
- Three public methods become permanently unusable: `Donate()`, `GetSymbolList()`, `GetUndistributedDividends()`
- Any transaction calling these methods will fail with null reference errors
- The dividend pool feature becomes completely non-functional for the entire lifetime of the side chain
- No recovery path exists - the contract cannot be reinitialized

**Who Is Affected:**
- All users attempting to donate to the side chain dividend pool
- Any services/dApps querying dividend pool information
- The entire side chain's economic reward distribution mechanism

**Severity Justification - High:**
While individual funds are not directly at risk, this creates a permanent operational failure of a core consensus contract feature with no remediation possible short of redeploying the entire chain.

### Likelihood Explanation

**Feasible Preconditions:**
The standard side chain deployment order shows TokenHolder IS deployed before Consensus: [10](#0-9) 

TokenHolder (line 21) deploys before Consensus (line 22), making this scenario unlikely in standard production deployments.

**Attack Complexity - Medium:**
This is not an "attack" but rather an operational failure scenario. It occurs when:
1. Custom deployment configurations omit or reorder TokenHolderContract
2. TokenHolder deployment fails but Consensus initialization proceeds
3. Test/development environments use minimal contract sets
4. Future maintenance changes deployment order

**Feasibility Conditions:**
The defensive check in the code suggests developers anticipated this scenario: [11](#0-10) 

The comment "No need to continue if Token Holder Contract didn't deployed" indicates intentional handling of absent TokenHolder. However, the incomplete implementation leaves public methods vulnerable.

**Probability - Low-Medium:**
Unlikely in standard deployments but realistic in non-standard configurations or deployment failures.

### Recommendation

Implement lazy initialization pattern consistent with other contract references:

```csharp
private void EnsureTokenHolderContractAddressSet()
{
    if (State.TokenHolderContract.Value == null)
    {
        State.TokenHolderContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName);
    }
}
```

Add null safety checks to all affected methods:

```csharp
public override Empty Donate(DonateInput input)
{
    EnsureTokenContractAddressSet();
    EnsureTokenHolderContractAddressSet();
    
    // If TokenHolder still not available, return gracefully
    if (State.TokenHolderContract.Value == null)
    {
        Context.LogDebug(() => "TokenHolder contract not available, donation not processed.");
        return new Empty();
    }
    
    // ... rest of method
}
```

Apply similar pattern to `GetSymbolList()` and `GetUndistributedDividends()`.

**Test Cases:**
1. Initialize consensus before TokenHolder deployment - verify graceful degradation
2. Call Donate/GetSymbolList/GetUndistributedDividends when TokenHolder unavailable - verify no crashes
3. Deploy TokenHolder after initialization - verify lazy initialization works
4. Standard deployment order - verify normal operation

### Proof of Concept

**Required Initial State:**
1. Deploy side chain with custom deployment list that excludes TokenHolder OR
2. Cause TokenHolder deployment to fail while Consensus initialization succeeds

**Transaction Steps:**
1. Call `InitialAElfConsensusContract()` with `IsSideChain = true`
2. `InitialProfitSchemeForSideChain()` executes, finds TokenHolder is null
3. Function returns early at line 24, `State.TokenHolderContract.Value` remains null
4. Later, user calls `Donate()` with valid input

**Expected vs Actual Result:**
- **Expected:** Donate should either work (if TokenHolder available) or gracefully decline (if optional)
- **Actual:** Transaction fails with null reference exception when executing line 59's `State.TokenHolderContract.ContributeProfits.Send()`

**Success Condition:**
The vulnerability is confirmed if calling `Donate()`, `GetSymbolList()`, or `GetUndistributedDividends()` after initialization without TokenHolder causes transaction failures with no recovery mechanism available.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L16-35)
```csharp
    private void InitialProfitSchemeForSideChain(long periodSeconds)
    {
        var tokenHolderContractAddress =
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName);
        // No need to continue if Token Holder Contract didn't deployed.
        if (tokenHolderContractAddress == null)
        {
            Context.LogDebug(() => "Token Holder Contract not found, so won't initial side chain dividends pool.");
            return;
        }

        State.TokenHolderContract.Value = tokenHolderContractAddress;
        State.TokenHolderContract.CreateScheme.Send(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = AEDPoSContractConstants.SideChainShareProfitsTokenSymbol,
            MinimumLockMinutes = periodSeconds.Div(60)
        });

        Context.LogDebug(() => "Side chain dividends pool created.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-65)
```csharp
    public override Empty Donate(DonateInput input)
    {
        EnsureTokenContractAddressSet();

        if (!State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = input.Symbol }).Value)
            return new Empty();

        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = Context.Self
        });

        State.TokenContract.Approve.Send(new ApproveInput
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            Spender = State.TokenHolderContract.Value
        });

        State.TokenHolderContract.ContributeProfits.Send(new ContributeProfitsInput
        {
            SchemeManager = Context.Self,
            Symbol = input.Symbol,
            Amount = input.Amount
        });

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L102-105)
```csharp
    public void Release()
    {
        if (State.TokenHolderContract.Value == null) return;
        var scheme = State.TokenHolderContract.GetScheme.Call(Context.Self);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L136-161)
```csharp
    public override SymbolList GetSymbolList(Empty input)
    {
        return new SymbolList
        {
            Value =
            {
                GetSideChainDividendPoolScheme().ReceivedTokenSymbols
            }
        };
    }

    public override Dividends GetUndistributedDividends(Empty input)
    {
        var scheme = GetSideChainDividendPoolScheme();
        return new Dividends
        {
            Value =
            {
                scheme.ReceivedTokenSymbols.Select(s => State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = s
                })).ToDictionary(b => b.Symbol, b => b.Balance)
            }
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L163-175)
```csharp
    private Scheme GetSideChainDividendPoolScheme()
    {
        if (State.SideChainDividendPoolSchemeId.Value == null)
        {
            var tokenHolderScheme = State.TokenHolderContract.GetScheme.Call(Context.Self);
            State.SideChainDividendPoolSchemeId.Value = tokenHolderScheme.SchemeId;
        }

        return Context.Call<Scheme>(
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName),
            nameof(ProfitContractContainer.ProfitContractReferenceState.GetScheme),
            State.SideChainDividendPoolSchemeId.Value);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L22-35)
```csharp
    public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
    {
        Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;

        State.PeriodSeconds.Value = input.IsTermStayOne
            ? int.MaxValue
            : input.PeriodSeconds;

        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;

        Context.LogDebug(() => $"There are {State.PeriodSeconds.Value} seconds per period.");

        if (input.IsSideChain) InitialProfitSchemeForSideChain(input.PeriodSeconds);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L140-159)
```csharp
    private void EnsureTokenContractAddressSet()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
    }

    private void EnsureElectionContractAddressSet()
    {
        if (State.ElectionContract.Value == null)
            State.ElectionContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
    }

    private void EnsureParliamentContractAddressSet()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ContractsReferences.cs (L10-20)
```csharp
// ReSharper disable once InconsistentNaming
// ReSharper disable UnusedAutoPropertyAccessor.Global
public partial class AEDPoSContractState
{
    internal ElectionContractContainer.ElectionContractReferenceState ElectionContract { get; set; }
    internal TreasuryContractImplContainer.TreasuryContractImplReferenceState TreasuryContract { get; set; }
    internal TokenContractContainer.TokenContractReferenceState TokenContract { get; set; }
    internal TokenHolderContractContainer.TokenHolderContractReferenceState TokenHolderContract { get; set; }
    internal ParliamentContractContainer.ParliamentContractReferenceState ParliamentContract { get; set; }
    internal ConfigurationContainer.ConfigurationReferenceState ConfigurationContract { get; set; }
}
```

**File:** src/AElf.Sdk.CSharp/State/MethodReference.cs (L18-21)
```csharp
    public void Send(TInput input)
    {
        _parent.Context.SendInline(_parent.Value, _name, input);
    }
```

**File:** src/AElf.Blockchains.SideChain/SideChainContractDeploymentListProvider.cs (L14-30)
```csharp
public class SideChainContractDeploymentListProvider : IContractDeploymentListProvider
{
    public List<Hash> GetDeployContractNameList()
    {
        return new List<Hash>
        {
            ProfitSmartContractAddressNameProvider.Name,
            TokenHolderSmartContractAddressNameProvider.Name,
            ConsensusSmartContractAddressNameProvider.Name,
            AssociationSmartContractAddressNameProvider.Name,
            ReferendumSmartContractAddressNameProvider.Name,
            ParliamentSmartContractAddressNameProvider.Name,
            TokenSmartContractAddressNameProvider.Name,
            CrossChainSmartContractAddressNameProvider.Name,
            ConfigurationSmartContractAddressNameProvider.Name
        };
    }
```
