### Title
Immutable TokenHolderContract Reference Prevents Dividend Pool Recovery After Contract Migration

### Summary
The AEDPoS side chain dividend pool's reference to the TokenHolder contract is set once during initialization and cannot be updated thereafter. If the TokenHolder system contract requires migration to a new address (not just a code update), the dividend pool becomes permanently non-functional with no recovery mechanism, trapping all donated funds.

### Finding Description
The TokenHolderContract reference is initialized once in `InitialProfitSchemeForSideChain` and stored in contract state: [1](#0-0) 

This initialization occurs only during the initial AEDPoS contract setup when `input.IsSideChain` is true: [2](#0-1) 

**Root Cause:** The contract reference is stored in state and never re-validated or updated. Unlike other system contract references (TokenContract, ElectionContract, ParliamentContract) which have `Ensure*AddressSet()` helper methods to refresh the address if null, no such mechanism exists for TokenHolderContract: [3](#0-2) 

**Why Protections Fail:** The `Release()` method contains only a null check that returns early, but never attempts to re-initialize: [4](#0-3) 

Additionally, the Genesis contract's `NameAddressMapping` prevents re-registration of system contract names: [5](#0-4) 

During normal contract updates via `UpdateSmartContract`, the address remains unchanged (only code and version change): [6](#0-5) 

However, if a critical bug necessitates complete redeployment to a new address, the AEDPoS contract would continue using the stale reference.

### Impact Explanation
**Operational Harm:** The dividend pool becomes completely non-functional:
- The `Donate` method relies on the TokenHolderContract reference for token approval and profit contribution: [7](#0-6) 

- The `Release` method uses it to retrieve scheme information and distribute profits: [8](#0-7) 

**Fund Impact:** All tokens donated to the dividend pool would be trapped, as:
1. New donations cannot be processed (Donate fails to interact with migrated TokenHolder)
2. Existing accumulated dividends cannot be released (Release fails to distribute)
3. No recovery mechanism exists to update the contract reference

**Affected Parties:** All side chain participants expecting dividend distributions from transaction fees and donations.

**Severity Justification:** Medium severity due to permanent loss of dividend pool functionality and trapped funds, though requires a system-level contract migration event to manifest.

### Likelihood Explanation
**Required Preconditions:**
- TokenHolder system contract must require migration to a completely new address
- This differs from standard `UpdateSmartContract` operations which preserve the address

**Feasibility:** 
- Normal contract updates only change code at the same address, so would not trigger this issue
- Complete address migration is rare but realistic for critical security vulnerabilities that cannot be patched via code update alone
- No attacker action required - this is a system upgrade failure scenario

**Complexity:** Low - once TokenHolder migrates, the failure manifests immediately on next Donate/Release call

**Detection:** The issue would be immediately apparent when dividend pool operations fail after TokenHolder migration

**Probability:** Medium - while complete contract migrations are infrequent, they are a realistic operational necessity that the system should handle gracefully

### Recommendation
**Code-Level Mitigation:**
1. Add an `EnsureTokenHolderContractAddressSet()` helper method to the AEDPoS contract following the existing pattern:
```csharp
private void EnsureTokenHolderContractAddressSet()
{
    if (State.TokenHolderContract.Value == null)
        State.TokenHolderContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName);
}
```

2. Call this helper before TokenHolderContract usage in `Donate`: [9](#0-8) 

3. Modify `Release()` to call the helper instead of just returning: [10](#0-9) 

4. Consider adding a governance-controlled method to force-update system contract references for emergency scenarios

**Invariant Check:** Contract should verify `State.TokenHolderContract.Value != null` and attempt re-initialization before each use

**Test Cases:**
- Test dividend pool operations after simulated TokenHolder contract migration
- Verify automatic re-initialization when contract reference becomes stale
- Test that helper correctly updates reference when underlying system contract changes

### Proof of Concept
**Initial State:**
1. Side chain AEDPoS contract initialized with TokenHolder at address `0xAAA...`
2. `State.TokenHolderContract.Value = 0xAAA...`
3. Dividend pool receiving donations successfully

**Migration Scenario:**
4. Critical bug discovered in TokenHolder contract requiring complete redeployment
5. New TokenHolder contract deployed at address `0xBBB...`
6. Genesis contract's `NameAddressMapping[TokenHolderContractSystemName]` updated to point to `0xBBB...` (assuming update mechanism exists)
7. AEDPoS contract's `State.TokenHolderContract.Value` still holds cached value `0xAAA...`

**Failure Manifestation:**
8. User calls `Donate(amount=1000, symbol="ELF")`
9. Line 56 executes: `State.TokenContract.Approve` sends approval to old address `0xAAA...` via `State.TokenHolderContract.Value`
10. Line 59 executes: `State.TokenHolderContract.ContributeProfits` calls old address `0xAAA...`
11. Transaction either fails or interacts with deprecated contract instance
12. User calls `Release()`
13. Line 105 executes: `State.TokenHolderContract.GetScheme` queries old address `0xAAA...`
14. Line 117 executes: `State.TokenHolderContract.DistributeProfits` calls old address `0xAAA...`
15. Distribution fails or uses stale scheme data

**Expected vs Actual:**
- **Expected:** Dividend pool operations use new TokenHolder contract at `0xBBB...`
- **Actual:** All operations continue using stale reference to `0xAAA...`, causing failures

**Success Condition:** Dividend pool becomes non-operational with no recovery path to update the contract reference.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L16-27)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-39)
```csharp
    public override Empty Donate(DonateInput input)
    {
        EnsureTokenContractAddressSet();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L52-64)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L102-121)
```csharp
    public void Release()
    {
        if (State.TokenHolderContract.Value == null) return;
        var scheme = State.TokenHolderContract.GetScheme.Call(Context.Self);
        var isTimeToRelease =
            (Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.PeriodSeconds.Value) > scheme.Period - 1;
        Context.LogDebug(() => "ReleaseSideChainDividendsPool Information:\n" +
                               $"CurrentBlockTime: {Context.CurrentBlockTime}\n" +
                               $"BlockChainStartTime: {State.BlockchainStartTimestamp.Value}\n" +
                               $"PeriodSeconds: {State.PeriodSeconds.Value}\n" +
                               $"Scheme Period: {scheme.Period}");
        if (isTimeToRelease)
        {
            Context.LogDebug(() => "Ready to release side chain dividends pool.");
            State.TokenHolderContract.DistributeProfits.Send(new DistributeProfitsInput
            {
                SchemeManager = Context.Self
            });
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L35-35)
```csharp
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L18-19)
```csharp
        if (name != null)
            Assert(State.NameAddressMapping[name] == null, "contract name has already been registered before");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L98-111)
```csharp
    private void UpdateSmartContract(Address contractAddress, byte[] code, Address author, bool isUserContract)
    {
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        Assert(author == info.Author, "No permission.");

        var oldCodeHash = info.CodeHash;
        var newCodeHash = HashHelper.ComputeFrom(code);
        Assert(oldCodeHash != newCodeHash, "Code is not changed.");
        AssertContractNotExists(newCodeHash);

        info.CodeHash = newCodeHash;
        info.IsUserContract = isUserContract;
        info.Version++;
```
