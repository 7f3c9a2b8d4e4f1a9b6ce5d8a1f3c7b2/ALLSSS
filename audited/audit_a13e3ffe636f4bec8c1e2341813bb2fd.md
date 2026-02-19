### Title
Profit Scheme Can Become Permanently Unmanageable When Contract Manager Is Upgraded

### Summary
When a profit scheme is created without specifying a manager, the creating contract becomes the manager by default. If this contract is later upgraded to a version that cannot execute profit management functions, critical scheme management operations (AddSubScheme, RemoveSubScheme, and ResetManager) become permanently locked with no recovery mechanism. This design flaw exists in production code where the Treasury contract manages multiple profit schemes.

### Finding Description

**Code Location:** [1](#0-0) 

When `CreateScheme` is called with `input.Manager` set to null, the manager defaults to `Context.Sender`. If the sender is a contract address, that contract becomes the scheme manager. 

**Real-World Example:** [2](#0-1) 

The Treasury contract creates seven profit schemes without specifying a manager, causing the Treasury contract itself to become the manager. While it later transfers two schemes to the Election contract, it retains management of five critical schemes.

**Manager-Only Functions Without Alternative Authorization:** [3](#0-2) [4](#0-3) [5](#0-4) 

These three functions strictly require `Context.Sender == scheme.Manager` with no fallback authorization mechanism (unlike other functions that allow TokenHolder contract as an alternative).

**Why Protections Fail:**
AElf supports contract upgrades where the address remains constant but the code changes. If a manager contract is upgraded to a version that:
- Removes profit management functionality
- Contains bugs preventing execution
- Is redesigned for different purposes

Then the manager address can no longer send the required transactions to call these functions. Since ResetManager is the only way to change the manager and itself requires being the current manager, there is no recovery path. No parliamentary override or administrative backdoor exists.

### Impact Explanation

**Direct Operational Impact:**
- `AddSubScheme` and `RemoveSubScheme` become permanently inaccessible, freezing the scheme's hierarchical structure
- `ResetManager` becomes permanently inaccessible, preventing transfer of management to a recoverable address
- The scheme structure becomes immutably locked in its current configuration

**Affected Functions:**
While `DistributeProfits`, `AddBeneficiary`, and `RemoveBeneficiary` have TokenHolder contract as alternative authorization, the critical structural management functions have no such fallback. [6](#0-5) 

**Severity Justification:**
Medium severity - This does not directly impact funds (profit distribution continues to work), but causes permanent denial of service for governance functions that control scheme structure. For critical system schemes like Treasury-managed profit schemes, this represents a significant operational risk that cannot be recovered without a hard fork.

### Likelihood Explanation

**Feasible Preconditions:**
- A contract creates a profit scheme without specifying a manager (demonstrated in production code)
- The contract is later upgraded through governance-approved processes
- The upgrade inadvertently removes or breaks the ability to call profit management functions

**Execution Practicality:**
Contract upgrades are a supported operation in AElf that preserve the contract address while changing code. This is not a theoretical scenario - the Treasury contract currently manages five profit schemes where this vulnerability applies.

**Realistic Scenarios:**
1. Contract refactoring that removes unused code paths, accidentally including profit management
2. Contract deprecation where a new version is deployed and the old contract is replaced
3. Security patches that introduce bugs in cross-contract calls
4. Intentional contract redesign that changes the contract's purpose

**Probability Assessment:**
While contract upgrades require governance approval (preventing purely malicious exploitation), the likelihood remains moderate because:
- The scenario can occur through legitimate operational changes
- No design safeguards exist to prevent this state
- Multiple system contracts follow this pattern
- The irreversibility of the consequence makes even low-probability events concerning

### Recommendation

**Immediate Mitigation:**
1. Require explicit manager specification in `CreateScheme` - remove the default fallback to `Context.Sender`
2. Add validation to prevent contract addresses from being set as managers without explicit acknowledgment
3. Implement a time-locked administrative override controlled by Parliament for emergency manager resets

**Code-Level Fix:**
```
Modify CreateScheme to require explicit manager:
Assert(input.Manager != null, "Manager must be explicitly specified.");
```

**Alternative Authorization:**
Add Parliament organization as fallback authorization for manager-only functions:
```
Assert(
    Context.Sender == scheme.Manager || 
    Context.Sender == GetParliamentDefaultOrganizationAddress(),
    "Only manager or parliament can perform this action.");
```

**State Migration:**
For existing schemes with contract managers (like Treasury), execute ResetManager to transfer management to EOA addresses or contracts with guaranteed upgrade continuity.

### Proof of Concept

**Initial State:**
1. Deploy Contract A with function to create profit schemes
2. Contract A calls `ProfitContract.CreateScheme(new CreateSchemeInput { Manager = null })`
3. Scheme is created with Contract A as manager [7](#0-6) 

**Upgrade Execution:**
4. Governance approves upgrade of Contract A to version 2
5. Version 2 removes or breaks the functionality to call `ProfitContract.ResetManager`
6. Attempt to call `AddSubScheme` on the scheme fails permanently

**Expected vs Actual Result:**
- **Expected**: System should prevent unrecoverable manager states or provide recovery mechanism
- **Actual**: Three critical management functions become permanently inaccessible with no recovery path

**Success Condition:**
The scheme's manager is set to a contract address that can no longer execute the required function calls, and verification confirms no alternative authorization path exists to recover management capabilities.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-58)
```csharp
        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L99-99)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only manager can add sub-scheme.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L139-139)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only manager can remove sub-scheme.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L729-729)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L60-67)
```csharp
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
                // Distribution of Citizen Welfare will delay one period.
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
```
