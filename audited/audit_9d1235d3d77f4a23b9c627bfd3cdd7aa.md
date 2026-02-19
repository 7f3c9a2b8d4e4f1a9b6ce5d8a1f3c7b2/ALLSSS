### Title
Contract Upgrade Denial of Service: Missing Interface Compatibility Validation Enables Permanent Voting Breakdown

### Summary
The Vote contract maintains a reference to TokenContract and calls critical methods (`IsInWhiteList`, `Lock`, `Unlock`) that are resolved by string name at runtime. When TokenContract is upgraded, there is no automated validation that existing method signatures are preserved. If TokenContract is upgraded with breaking interface changes that remove or rename these methods, all voting operations would fail with runtime exceptions, requiring Vote contract redeployment through governance to restore functionality.

### Finding Description

**Root Cause:**

The AElf contract upgrade mechanism lacks interface compatibility validation. When a contract is upgraded through `ProposeUpdateContract`, the system only validates:
1. Semantic version must be higher [1](#0-0) 
2. Deployment mode compatibility (ContractOperation) [2](#0-1) 
3. Required ACS standards are implemented

There is **no check** that ensures dependent contracts' method calls will continue to work after the upgrade.

**Vulnerable Contract Reference:**

Vote contract declares a TokenContract reference: [3](#0-2) 

The Vote contract critically depends on three TokenContract methods:

1. `Register()` calls `IsInWhiteList`: [4](#0-3) 

2. `Vote()` calls `Lock`: [5](#0-4) 

3. `Withdraw()` calls `Unlock`: [6](#0-5) 

**Why Method Resolution Fails:**

Contract method calls use string-based method names resolved at runtime: [7](#0-6) 

At execution time, if the method doesn't exist in the upgraded contract, the system throws a RuntimeException: [8](#0-7) 

This causes the transaction to fail with `ExecutionStatus.SystemError`: [9](#0-8) 

**Why Existing Protections Fail:**

The TokenContract interface defines these methods in the protobuf specification: [10](#0-9) 

However, during upgrade, the system does not validate that these method signatures remain unchanged. The compatibility check in the upgrade process only validates deployment mode compatibility, not interface preservation.

### Impact Explanation

**Operational Impact - Complete Voting System DOS:**

If TokenContract is upgraded and the `Lock`, `Unlock`, or `IsInWhiteList` methods are removed, renamed, or have incompatible signatures:

1. **Register()** fails - No new voting items can be created (affects all voting sponsors)
2. **Vote()** fails - No votes can be cast (affects all voters)  
3. **Withdraw()** fails - Locked tokens cannot be retrieved (affects all active voters)

**Affected Contracts:**

Multiple system contracts depend on these TokenContract methods:
- Vote contract (voting registration, voting, withdrawal)
- Election contract (candidate voting, profit claiming) [11](#0-10) 
- TokenHolder contract (dividend claims) [12](#0-11) 
- Treasury contract (treasury operations) [13](#0-12) 

**Recovery Complexity:**

Recovery requires:
1. Detecting the broken functionality (users report vote failures)
2. Developing updated Vote contract code to match new TokenContract interface
3. Creating governance proposal via `ProposeUpdateContract` [14](#0-13) 
4. Obtaining ContractDeploymentController approval (miner consensus)
5. Obtaining CodeCheckController approval (code verification)
6. Deploying the fixed contract

This process could take **days to weeks**, during which the entire voting system remains non-functional.

### Likelihood Explanation

**Preconditions:**

1. Developer creates new TokenContract version that refactors/renames/removes `Lock`, `Unlock`, or `IsInWhiteList` methods
2. Governance review doesn't catch the interface breaking change
3. Both ContractDeploymentController and CodeCheckController approve the upgrade
4. Upgrade is executed

**Feasibility Analysis:**

This scenario is **realistic** because:

1. **No Automated Protection:** The upgrade validation has no interface compatibility checker. Human reviewers must manually verify all dependent contracts.

2. **Complex Dependency Graph:** TokenContract is called by Vote, Election, TokenHolder, and Treasury contracts. Tracking all dependencies manually is error-prone.

3. **Legitimate Refactoring:** Developers might rename methods for clarity (e.g., `Lock` → `LockTokens`) or consolidate functionality without realizing the breaking change.

4. **Governance Focus:** Governance review typically focuses on security vulnerabilities and correctness, not interface compatibility with dependent contracts.

**Attack Complexity:** MEDIUM
- Requires governance approval (not unilateral)
- But doesn't require malicious intent - can happen accidentally
- No automated checks to prevent it

**Detection:** POST-EXPLOITATION
- Only detected after upgrade when voting operations start failing
- No pre-deployment compatibility testing framework exists

### Recommendation

**1. Implement Pre-Upgrade Interface Compatibility Validation:**

Add a compatibility validator in `BasicContractZero.ProposeUpdateContract` that:
- Extracts method signatures from the old contract version
- Compares with method signatures in the proposed upgrade
- Fails the proposal if any existing public methods are removed or have incompatible signatures

**2. Create Dependency Registry:**

Maintain a registry in BasicContractZero that tracks inter-contract dependencies:
```
State.ContractDependencies[TokenContractAddress][VoteContractAddress] = ["Lock", "Unlock", "IsInWhiteList"]
```

During upgrade validation, check all dependent contracts for method compatibility.

**3. Add Integration Tests:**

Create regression tests that simulate contract upgrades and verify dependent contracts still function:
- Deploy Vote and TokenContract
- Upgrade TokenContract with breaking changes
- Verify that Vote contract operations fail as expected
- Add this as a negative test case to prevent accidental merging

**4. Deprecation Process:**

If breaking changes are necessary, implement a two-phase deprecation:
- Phase 1: Add new methods while keeping old ones (mark as deprecated)
- Phase 2: After all dependent contracts upgraded, remove deprecated methods

### Proof of Concept

**Initial State:**
- Vote contract deployed at address V
- TokenContract deployed at address T with methods: `Lock`, `Unlock`, `IsInWhiteList`
- Vote contract state: `State.TokenContract.Value = T`

**Attack Sequence:**

1. **Propose Incompatible Upgrade:**
   - Developer creates TokenContract_v2 that renames `Lock` → `LockTokensForVoting`
   - Call `BasicContractZero.ProposeUpdateContract(ContractUpdateInput{Address: T, Code: TokenContract_v2})`
   - System validates version number and ACS compliance ✓
   - System does NOT validate that dependent contracts will break ✗

2. **Governance Approves:**
   - ContractDeploymentController approves (miners vote)
   - CodeCheckController approves (code verification passes)
   - Call `ReleaseCodeCheckedContract` to execute upgrade
   - TokenContract is now running v2 code

3. **Voting System Breaks:**
   - User calls `VoteContract.Vote(input)` 
   - Vote contract executes: `State.TokenContract.Lock.Send(lockInput)`
   - This translates to: `Context.SendInline(T, "Lock", lockInput)`
   - Executive.Execute() in TokenContract_v2 tries to find handler for "Lock"
   - Method not found → RuntimeException thrown
   - Transaction fails with ExecutionStatus.SystemError

**Expected Result:**
Vote transaction succeeds and tokens are locked.

**Actual Result:**
Vote transaction fails with error: "Failed to find handler for Lock"

**Success Condition:**
All voting operations (Register, Vote, Withdraw) fail consistently until Vote contract is redeployed with updated method names, which requires full governance approval cycle.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L124-127)
```csharp
        var contractInfo = Context.UpdateSmartContract(contractAddress, reg, null, info.ContractVersion);
        Assert(contractInfo.IsSubsequentVersion,
            $"The version to be deployed is lower than the effective version({info.ContractVersion}), please correct the version number.");

```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L175-232)
```csharp
    public override Hash ProposeUpdateContract(ContractUpdateInput input)
    {
        var proposedContractInputHash = CalculateHashFromInput(input);
        RegisterContractProposingData(proposedContractInputHash);

        var contractAddress = input.Address;
        var info = State.ContractInfos[contractAddress];
        Assert(info != null, "Contract not found.");
        AssertAuthorityByContractInfo(info, Context.Sender);
        AssertContractVersion(info.ContractVersion, input.Code, info.Category);

        var codeHash = HashHelper.ComputeFrom(input.Code.ToByteArray());
        AssertContractNotExists(codeHash);

        Assert((input.Address == Context.Self || info.SerialNumber > 0) && input.ContractOperation == null ||
               info.SerialNumber == 0 && input.ContractOperation != null, "Not compatible.");

        if (input.ContractOperation != null)
        {
            ValidateContractOperation(input.ContractOperation, info.Version, codeHash);
            RemoveOneTimeSigner(input.ContractOperation.Deployer);
            AssertSameDeployer(input.Address, input.ContractOperation.Deployer);
        }

        var expirationTimePeriod = GetCurrentContractProposalExpirationTimePeriod();

        // Create proposal for contract update
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
                    CodeCheckReleaseMethod = nameof(UpdateSmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = info.Category,
                    IsSystemContract = info.IsSystemContract
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput);

        Context.Fire(new ContractProposed
        {
            ProposedContractInputHash = proposedContractInputHash
        });

        return proposedContractInputHash;
    }
```

**File:** contract/AElf.Contracts.Vote/ContractsReferences.cs (L8-8)
```csharp
    internal TokenContractContainer.TokenContractReferenceState TokenContract { get; set; }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L29-34)
```csharp
        var isInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
        {
            Symbol = input.AcceptedCurrency,
            Address = Context.Self
        }).Value;
        Assert(isInWhiteList, "Claimed accepted token is not available for voting.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L124-130)
```csharp
            State.TokenContract.Lock.Send(new LockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                LockId = input.VoteId,
                Amount = amount
            });
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L225-231)
```csharp
            State.TokenContract.Unlock.Send(new UnlockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                Amount = votingRecord.Amount,
                LockId = input.VoteId
            });
```

**File:** src/AElf.Sdk.CSharp/State/MethodReference.cs (L18-26)
```csharp
    public void Send(TInput input)
    {
        _parent.Context.SendInline(_parent.Value, _name, input);
    }

    public TOutput Call(TInput input)
    {
        return _parent.Context.Call<TOutput>(_parent.Value, _name, input);
    }
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L133-137)
```csharp
            if (!_callHandlers.TryGetValue(methodName, out var handler))
                throw new RuntimeException(
                    $"Failed to find handler for {methodName}. We have {_callHandlers.Count} handlers: " +
                    string.Join(", ", _callHandlers.Keys.OrderBy(k => k))
                );
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L148-150)
```csharp
        catch (Exception ex)
        {
            CurrentTransactionContext.Trace.ExecutionStatus = ExecutionStatus.SystemError;
```

**File:** protobuf/token_contract.proto (L51-57)
```text
    // This method can be used to lock tokens.
    rpc Lock (LockInput) returns (google.protobuf.Empty) {
    }

    // This is the reverse operation of locking, it un-locks some previously locked tokens.
    rpc Unlock (UnlockInput) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L272-272)
```csharp
        State.TokenContract.Unlock.Send(new UnlockInput
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-159)
```csharp
        State.TokenContract.Lock.Send(new LockInput
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L296-296)
```csharp
            var isTreasuryInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
```
