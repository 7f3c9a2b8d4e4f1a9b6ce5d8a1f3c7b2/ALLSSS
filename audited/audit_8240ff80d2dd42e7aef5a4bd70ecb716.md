### Title
Unbounded Gas Consumption in VotingRegisterInput.GetHash Due to Unnecessary Deep Copy of Options Array

### Summary
The `GetHash` extension method for `VotingRegisterInput` performs an expensive deep copy of the entire input object including potentially large options arrays, only to immediately discard the options. The `Register` method does not validate options count or length before calling `GetHash`, allowing attackers to submit voting registrations with arbitrarily large options arrays (bounded only by the 5MB transaction size limit), causing excessive resource consumption and potential transaction failures.

### Finding Description

The vulnerability exists in the first `GetHash` method in VoteExtensions.cs: [1](#0-0) 

At line 9, the method calls `Clone()` which performs a deep copy of the entire `VotingRegisterInput` object, including all elements in the `options` repeated field. The protobuf `Clone()` method creates full copies of all nested data structures. Immediately after at line 10, the cloned options are cleared before hashing, making the expensive cloning operation completely wasteful.

The `VotingRegisterInput` protobuf message contains a `repeated string options` field that can hold multiple option strings: [2](#0-1) 

The `Register` method calls `GetHash` through `AssertValidNewVotingItem` without any prior validation of the options array: [3](#0-2) 

At line 354, `GetHash` is invoked immediately, before any checks on the options count or individual option lengths. The contract defines constants `MaximumOptionsCount = 64` and `OptionLengthLimit = 1024`: [4](#0-3) 

However, these limits are only enforced when adding options after registration via `AddOption` or `AddOptions` methods: [5](#0-4) [6](#0-5) 

The validation at lines 285-286 and 320-321 occurs only for post-registration option modifications, not during initial registration. This allows an attacker to bypass these limits by including arbitrarily large options arrays in the initial `Register` call.

### Impact Explanation

**Operational Impact - Resource Exhaustion DoS:**

An attacker can craft a `Register` transaction containing a `VotingRegisterInput` with:
- Hundreds or thousands of options (no limit enforced during registration)
- Each option containing up to 1024 characters or more (no length validation during registration)
- Total payload approaching the transaction size limit of 5MB: [7](#0-6) 

When such a transaction is processed, the `Clone()` operation will:
1. Allocate memory for the entire cloned object
2. Deep copy all option strings (potentially megabytes of data)
3. Consume significant computational resources
4. Immediately discard the cloned options

This excessive resource consumption can lead to:
- Transaction failure due to resource token exhaustion (AElf uses READ/WRITE/STORAGE/TRAFFIC resource tokens for execution metering)
- Wasted blockchain resources even if the transaction succeeds
- Griefing attacks where attackers force honest users to pay higher costs for legitimate voting registrations
- Potential denial of service if multiple such transactions are submitted

**Severity Justification:** Medium severity because while this doesn't directly steal funds or compromise governance, it enables resource exhaustion attacks on the voting system and violates reasonable gas cost expectations. The 5MB transaction size limit provides partial mitigation but doesn't eliminate the inefficiency.

### Likelihood Explanation

**Reachable Entry Point:** The `Register` method is a public RPC endpoint accessible to any user: [8](#0-7) 

**Feasible Preconditions:** 
- No special privileges required
- Attacker only needs to craft a valid transaction with a large options array
- The vulnerability is deterministic and always triggers when a large options array is provided

**Execution Practicality:**
- Attack is straightforward - simply submit `Register` with VotingRegisterInput containing many large options
- No timing dependencies or complex state manipulation required
- Can be executed from any account

**Economic Rationality:**
- Attacker pays normal transaction fees but forces the system to do wasteful computation
- Cost-benefit ratio favors the attacker in griefing scenarios
- Multiple such transactions could be submitted to amplify the effect

**Probability:** High - the vulnerability is inherent in the code design and will manifest whenever large options arrays are provided during registration.

### Recommendation

**Immediate Fix:** Refactor the first `GetHash` method to avoid unnecessary cloning of the options array:

```csharp
public static Hash GetHash(this VotingRegisterInput votingItemInput, Address sponsorAddress)
{
    // Create new object with only needed fields instead of cloning entire input
    var input = new VotingRegisterInput
    {
        StartTimestamp = votingItemInput.StartTimestamp,
        EndTimestamp = votingItemInput.EndTimestamp,
        AcceptedCurrency = votingItemInput.AcceptedCurrency,
        IsLockToken = votingItemInput.IsLockToken,
        TotalSnapshotNumber = votingItemInput.TotalSnapshotNumber,
        IsQuadratic = votingItemInput.IsQuadratic,
        TicketCost = votingItemInput.TicketCost
        // Intentionally omit Options field
    };
    return HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(input), HashHelper.ComputeFrom(sponsorAddress));
}
```

**Additional Validation:** Add input validation in `AssertValidNewVotingItem` before calling `GetHash`:

```csharp
private Hash AssertValidNewVotingItem(VotingRegisterInput input)
{
    // Validate options count
    Assert(input.Options.Count <= VoteContractConstants.MaximumOptionsCount,
        $"Options count cannot exceed {VoteContractConstants.MaximumOptionsCount}");
    
    // Validate each option length
    foreach (var option in input.Options)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit,
            $"Option length cannot exceed {VoteContractConstants.OptionLengthLimit}");
    }
    
    var votingItemId = input.GetHash(Context.Sender);
    // ... rest of existing code
}
```

**Test Cases:** Add regression tests to verify:
1. Registration with MaximumOptionsCount options succeeds
2. Registration with MaximumOptionsCount + 1 options fails
3. Registration with any option exceeding OptionLengthLimit fails
4. Gas consumption for registration scales linearly with validated input size

### Proof of Concept

**Step 1 - Initial State:** Deploy Vote contract with standard configuration.

**Step 2 - Craft Malicious Input:** Create `VotingRegisterInput` with 1000 options, each containing 1000 characters:

```csharp
var maliciousInput = new VotingRegisterInput
{
    StartTimestamp = Timestamp.FromDateTime(DateTime.UtcNow),
    EndTimestamp = Timestamp.FromDateTime(DateTime.UtcNow.AddDays(10)),
    AcceptedCurrency = "ELF",
    IsLockToken = true,
    TotalSnapshotNumber = 1,
    Options = { Enumerable.Range(0, 1000).Select(i => new string('A', 1000)) }
};
```

**Step 3 - Submit Transaction:** Call `Register(maliciousInput)`.

**Expected Result:** Transaction should validate options and reject if exceeding limits, with gas cost proportional to actual data size.

**Actual Result:** Transaction processes the `Clone()` operation copying ~1MB of option data, then immediately discards it. The cloning cost is paid but wasted. If resource tokens are insufficient, transaction fails. If it succeeds, blockchain resources are unnecessarily consumed.

**Success Condition:** An attacker successfully forces the contract to perform expensive clone operations on data that is immediately discarded, demonstrating the inefficiency and potential for resource exhaustion attacks.

### Notes

The second `GetHash` method for `VotingResult` is NOT vulnerable: [9](#0-8) 

This method safely creates a new `VotingResult` object containing only the two fixed-size fields `VotingItemId` and `SnapshotNumber`, regardless of how large the `results` map is in the original object. No unnecessary copying occurs.

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

**File:** protobuf/vote_contract.proto (L16-21)
```text
service VoteContract {
    option (aelf.csharp_state) = "AElf.Contracts.Vote.VoteContractState";

    // Create a voting activity.
    rpc Register (VotingRegisterInput) returns (google.protobuf.Empty) {
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L280-290)
```csharp
    public override Empty AddOption(AddOptionInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        AssertOption(votingItem, input.Option);
        Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
        votingItem.Options.Add(input.Option);
        State.VotingItems[votingItem.VotingItemId] = votingItem;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L314-324)
```csharp
    public override Empty AddOptions(AddOptionsInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        foreach (var option in input.Options) AssertOption(votingItem, option);
        votingItem.Options.AddRange(input.Options);
        Assert(votingItem.Options.Count <= VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
        State.VotingItems[votingItem.VotingItemId] = votingItem;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L351-366)
```csharp
    private Hash AssertValidNewVotingItem(VotingRegisterInput input)
    {
        // Use input without options and sender's address to calculate voting item id.
        var votingItemId = input.GetHash(Context.Sender);

        Assert(State.VotingItems[votingItemId] == null, "Voting item already exists.");

        // total snapshot number can't be 0. At least one epoch is required.
        if (input.TotalSnapshotNumber == 0) input.TotalSnapshotNumber = 1;

        Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");

        Context.LogDebug(() => $"Voting item created by {Context.Sender}: {votingItemId.ToHex()}");

        return votingItemId;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L1-7)
```csharp
namespace AElf.Contracts.Vote;

public static class VoteContractConstants
{
    public const int MaximumOptionsCount = 64;
    public const int OptionLengthLimit = 1024;
}
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L1-6)
```csharp
namespace AElf.Kernel.TransactionPool;

public class TransactionPoolConsts
{
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
}
```
