### Title
Protobuf Upgrade Breaks VotingRegisterInput Hash Determinism Leading to Voting Item Lookup Failures

### Summary
The `VotingRegisterInput.GetHash()` method uses `Clone()` to copy all protobuf fields before computing the hash, which means adding new fields to the `VotingRegisterInput` protobuf definition would change the computed hash for logically identical voting items. This breaks the deterministic hash computation assumption used throughout the system, potentially making existing voting items unfindable and allowing duplicate voting items to be created after protobuf upgrades.

### Finding Description

**Root Cause:** 
The `VotingRegisterInput.GetHash()` extension method at [1](#0-0)  clones the entire input protobuf message and only clears the `options` field before hashing. When `HashHelper.ComputeFrom(input)` is called at [2](#0-1) , it serializes the message using `ToByteArray()`, which includes ALL non-default fields in the protobuf serialization.

**Current VotingRegisterInput Structure:**
The protobuf definition contains 8 fields [3](#0-2) . If new fields (e.g., field 9) are added to this definition and have non-default values, they will be included in the cloned input and affect the serialization output, thus changing the hash.

**Contrasting Safe Pattern:**
The `VotingResult.GetHash()` method demonstrates the correct approach at [4](#0-3) . It explicitly creates a NEW `VotingResult` object with only the two fields needed for the hash (`VotingItemId` and `SnapshotNumber`), making it immune to protobuf schema evolution.

**Critical Usage in Election Contract:**
The Election contract computes and stores the voting item ID using `HashHelper.ComputeFrom(votingRegisterInput)` at [5](#0-4) . This same computation pattern is used in tests to recompute voting item IDs at [6](#0-5) , demonstrating the system-wide assumption of hash determinism.

**Vulnerability Execution Path:**
The Vote contract's `Register` method uses `GetHash()` to compute the voting item ID at [7](#0-6) , then checks for duplicates. After a protobuf upgrade with new fields, the same logical voting parameters would produce a different hash, bypassing the duplicate check.

### Impact Explanation

**Operational Impact - Data Integrity Failure:**
1. **Voting Item Lookup Failures**: Any system component that recomputes voting item IDs from registration parameters (as shown in the test helper pattern) would generate incorrect hashes post-upgrade, making existing voting items unfindable.

2. **Duplicate Voting Item Creation**: The duplicate check at [8](#0-7)  would fail to detect logically identical voting items registered before and after a protobuf upgrade, allowing multiple "duplicate" voting items with different hashes.

3. **Cross-Contract State Inconsistency**: The Election contract stores `MinerElectionVotingItemId` and uses it for critical operations like `TakeSnapshot` at [9](#0-8)  and adding/removing candidate options at [10](#0-9) . While stored IDs remain valid, any recomputation logic breaks.

**Historical Evidence of Protobuf Evolution:**
The codebase shows evidence of protobuf evolution where fields were added (e.g., `is_quadratic` and `ticket_cost` as fields 7-8 in the current definition), and similar patterns exist in other contracts where fields like `random_number` were added for compatibility, demonstrating that protobuf upgrades are a real operational scenario in this system.

### Likelihood Explanation

**High Likelihood - Realistic Scenario:**

1. **Reachable Entry Point**: The `Register` method is publicly accessible at [11](#0-10) , allowing any address to create voting items.

2. **Feasible Preconditions**: 
   - Protobuf schema evolution is a standard maintenance operation
   - The current `VotingRegisterInput` has already been extended (fields 7-8 for quadratic voting)
   - Contract upgrade mechanisms exist at [12](#0-11)  showing upgrades are routine

3. **Automatic Trigger**: No attacker action needed - the vulnerability triggers automatically when:
   - A protobuf upgrade adds new fields to `VotingRegisterInput`
   - Any component attempts to recompute voting item IDs
   - New voting items are registered with parameters matching pre-upgrade items

4. **System-Wide Impact**: The pattern of hash recomputation is embedded in test infrastructure and likely in off-chain indexing systems, affecting ecosystem-wide tooling.

### Recommendation

**Immediate Fix - Adopt Explicit Field Selection Pattern:**

Modify `VotingRegisterInput.GetHash()` to explicitly construct a minimal object with only the fields that should contribute to the hash:

```csharp
public static Hash GetHash(this VotingRegisterInput votingItemInput, Address sponsorAddress)
{
    var hashInput = new VotingRegisterInput
    {
        StartTimestamp = votingItemInput.StartTimestamp,
        EndTimestamp = votingItemInput.EndTimestamp,
        AcceptedCurrency = votingItemInput.AcceptedCurrency,
        IsLockToken = votingItemInput.IsLockToken,
        TotalSnapshotNumber = votingItemInput.TotalSnapshotNumber,
        IsQuadratic = votingItemInput.IsQuadratic,
        TicketCost = votingItemInput.TicketCost
        // Explicitly exclude 'options' and any future fields from hash
    };
    return HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(hashInput), HashHelper.ComputeFrom(sponsorAddress));
}
```

**Additional Safeguards:**

1. Add protobuf versioning/compatibility tests that verify hash stability across schema upgrades
2. Document which fields contribute to voting item ID computation
3. Add compile-time checks or comments warning against modifying hash-contributing fields
4. Consider adding a version field to `VotingRegisterInput` to track schema changes

**Regression Tests:**

Create tests that:
1. Register a voting item with specific parameters
2. Simulate adding a new field to the protobuf (via test mock)
3. Verify the hash remains identical when the new field has default values
4. Verify the hash remains identical when the new field has non-default values

### Proof of Concept

**Scenario: Protobuf Upgrade Breaks Voting Item Lookup**

**Initial State (Before Upgrade):**
1. `VotingRegisterInput` has fields 1-8 as currently defined at [3](#0-2) 
2. Election contract registers the miner election voting item during initialization
3. Voting item ID is computed and stored: `Hash_A = HashHelper.ComputeFrom(votingRegisterInput_without_options)`

**Upgrade Event:**
1. System governance approves Vote contract upgrade
2. Protobuf definition updated to add field 9 (e.g., `int64 new_parameter = 9;`)
3. Contract code updated via [13](#0-12) 

**Post-Upgrade State:**
1. Any system attempting to recompute the voting item ID from the same parameters (as done in test helper at [6](#0-5) ) will now get: `Hash_B = HashHelper.ComputeFrom(votingRegisterInput_with_field9)`
2. `Hash_A ≠ Hash_B` because protobuf serialization now includes field 9
3. Lookup using `Hash_B` fails at [14](#0-13) 
4. New registration with identical logical parameters succeeds (bypasses duplicate check), creating duplicate voting item

**Expected Result:** Voting item should remain findable with deterministic hash computation

**Actual Result:** Hash mismatch causes lookup failures and duplicate voting item vulnerability

### Citations

**File:** contract/AElf.Contracts.Vote/VoteExtensions.cs (L7-12)
```csharp
    public static Hash GetHash(this VotingRegisterInput votingItemInput, Address sponsorAddress)
    {
        var input = votingItemInput.Clone();
        input.Options.Clear();
        return HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(input), HashHelper.ComputeFrom(sponsorAddress));
    }
```

**File:** contract/AElf.Contracts.Vote/VoteExtensions.cs (L14-21)
```csharp
    public static Hash GetHash(this VotingResult votingResult)
    {
        return HashHelper.ComputeFrom(new VotingResult
        {
            VotingItemId = votingResult.VotingItemId,
            SnapshotNumber = votingResult.SnapshotNumber
        });
    }
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L55-58)
```csharp
        public static Hash ComputeFrom(IMessage message)
        {
            return ComputeFrom(message.ToByteArray());
        }
```

**File:** protobuf/vote_contract.proto (L87-104)
```text
message VotingRegisterInput {
    // The start time of the voting.
    google.protobuf.Timestamp start_timestamp = 1;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 2;
    // The token symbol which will be accepted.
    string accepted_currency = 3;
    // Whether the vote will lock token.
    bool is_lock_token = 4;
    // The total number of snapshots of the vote.
    int64 total_snapshot_number = 5;
    // The list of options.
    repeated string options = 6;
    // Is quadratic voting.
    bool is_quadratic = 7;
    // Quadratic voting item ticket cost.
    int64 ticket_cost = 8;
}
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L60-72)
```csharp
        var votingRegisterInput = new VotingRegisterInput
        {
            IsLockToken = false,
            AcceptedCurrency = Context.Variables.NativeSymbol,
            TotalSnapshotNumber = long.MaxValue,
            StartTimestamp = TimestampHelper.MinValue,
            EndTimestamp = TimestampHelper.MaxValue
        };
        State.VoteContract.Register.Send(votingRegisterInput);

        State.MinerElectionVotingItemId.Value = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(votingRegisterInput),
            HashHelper.ComputeFrom(Context.Self));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L308-317)
```csharp
            State.VoteContract.RemoveOption.Send(new RemoveOptionInput
            {
                VotingItemId = State.MinerElectionVotingItemId.Value,
                Option = oldPubkey
            });
            State.VoteContract.AddOption.Send(new AddOptionInput
            {
                VotingItemId = State.MinerElectionVotingItemId.Value,
                Option = newPubkey
            });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L422-426)
```csharp
        State.VoteContract.TakeSnapshot.Send(new TakeSnapshotInput
        {
            SnapshotNumber = input.TermNumber,
            VotingItemId = State.MinerElectionVotingItemId.Value
        });
```

**File:** test/AElf.Contracts.Vote.Tests/VoteContractTestHelper.cs (L44-45)
```csharp
        input.Options.Clear();
        var votingItemId = HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(input), HashHelper.ComputeFrom(sender));
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-82)
```csharp
    public override Empty Register(VotingRegisterInput input)
    {
        var votingItemId = AssertValidNewVotingItem(input);

        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Accepted currency is in white list means this token symbol supports voting.
        var isInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
        {
            Symbol = input.AcceptedCurrency,
            Address = Context.Self
        }).Value;
        Assert(isInWhiteList, "Claimed accepted token is not available for voting.");

        // Initialize voting event.
        var votingItem = new VotingItem
        {
            Sponsor = Context.Sender,
            VotingItemId = votingItemId,
            AcceptedCurrency = input.AcceptedCurrency,
            IsLockToken = input.IsLockToken,
            TotalSnapshotNumber = input.TotalSnapshotNumber,
            CurrentSnapshotNumber = 1,
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
            RegisterTimestamp = Context.CurrentBlockTime,
            Options = { input.Options },
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
        };

        State.VotingItems[votingItemId] = votingItem;

        // Initialize first voting going information of registered voting event.
        var votingResultHash = GetVotingResultHash(votingItemId, 1);
        State.VotingResults[votingResultHash] = new VotingResult
        {
            VotingItemId = votingItemId,
            SnapshotNumber = 1,
            SnapshotStartTimestamp = input.StartTimestamp
        };

        Context.Fire(new VotingItemRegistered
        {
            Sponsor = votingItem.Sponsor,
            VotingItemId = votingItemId,
            AcceptedCurrency = votingItem.AcceptedCurrency,
            IsLockToken = votingItem.IsLockToken,
            TotalSnapshotNumber = votingItem.TotalSnapshotNumber,
            CurrentSnapshotNumber = votingItem.CurrentSnapshotNumber,
            CurrentSnapshotStartTimestamp = votingItem.StartTimestamp,
            StartTimestamp = votingItem.StartTimestamp,
            EndTimestamp = votingItem.EndTimestamp,
            RegisterTimestamp = votingItem.RegisterTimestamp,
            IsQuadratic = votingItem.IsQuadratic,
            TicketCost = votingItem.TicketCost
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L351-356)
```csharp
    private Hash AssertValidNewVotingItem(VotingRegisterInput input)
    {
        // Use input without options and sender's address to calculate voting item id.
        var votingItemId = input.GetHash(Context.Sender);

        Assert(State.VotingItems[votingItemId] == null, "Voting item already exists.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L1-50)
```csharp
using System;
using AElf.Contracts.Parliament;
using AElf.CSharp.Core.Extension;
using AElf.Sdk.CSharp;
using AElf.Standards.ACS0;
using AElf.Standards.ACS3;
using AElf.Types;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace AElf.Contracts.Genesis;

public partial class BasicContractZero
{
    private Address DeploySmartContract(Hash name, int category, byte[] code, bool isSystemContract,
        Address author, bool isUserContract, Address deployer = null, Hash salt = null)
    {
        if (name != null)
            Assert(State.NameAddressMapping[name] == null, "contract name has already been registered before");

        var codeHash = HashHelper.ComputeFrom(code);
        AssertContractNotExists(codeHash);

        long serialNumber;
        Address contractAddress;

        if (salt == null)
        {
            serialNumber = State.ContractSerialNumber.Value;
            // Increment
            State.ContractSerialNumber.Value = serialNumber + 1;
            contractAddress = AddressHelper.ComputeContractAddress(Context.ChainId, serialNumber);
        }
        else
        {
            serialNumber = 0;
            contractAddress = AddressHelper.ComputeContractAddress(deployer, salt);
        }

        Assert(State.ContractInfos[contractAddress] == null, "Contract address exists.");

        var info = new ContractInfo
        {
            SerialNumber = serialNumber,
            Author = author,
            Category = category,
            CodeHash = codeHash,
            IsSystemContract = isSystemContract,
            Version = 1,
            IsUserContract = isUserContract,
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L1-50)
```csharp
using AElf.CSharp.Core.Extension;
using AElf.Sdk.CSharp;
using AElf.Standards.ACS0;
using AElf.Standards.ACS3;
using AElf.Types;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace AElf.Contracts.Genesis;

public partial class BasicContractZero : BasicContractZeroImplContainer.BasicContractZeroImplBase
{
    #region Views

    public override Int64Value CurrentContractSerialNumber(Empty input)
    {
        return new Int64Value { Value = State.ContractSerialNumber.Value };
    }

    public override ContractInfo GetContractInfo(Address input)
    {
        var info = State.ContractInfos[input];
        if (info == null) return new ContractInfo();

        return info;
    }

    public override Address GetContractAuthor(Address input)
    {
        var info = State.ContractInfos[input];
        return info?.Author;
    }

    public override Hash GetContractHash(Address input)
    {
        var info = State.ContractInfos[input];
        return info?.CodeHash;
    }

    public override Address GetContractAddressByName(Hash input)
    {
        var address = State.NameAddressMapping[input];
        return address;
    }

    public override SmartContractRegistration GetSmartContractRegistrationByAddress(Address input)
    {
        var info = State.ContractInfos[input];
        if (info == null) return null;

```

**File:** contract/AElf.Contracts.Vote/VoteContractState.cs (L9-9)
```csharp
    public MappedState<Hash, VotingItem> VotingItems { get; set; }
```
