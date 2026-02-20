# Audit Report

## Title
Missing Options Count Validation During Registration Allows Unlimited Options

## Summary
The `Register()` function in VoteContract fails to validate the number of options during voting item creation, allowing any user to bypass the intended 64-option limit by registering voting items with unlimited options. This creates an inconsistency where post-registration option additions enforce the limit, but initial registration does not.

## Finding Description

The VoteContract establishes a maximum option count constraint of 64 through the `MaximumOptionsCount` constant. [1](#0-0) 

The `Register()` function directly assigns the input options array to the voting item without any count validation. [2](#0-1) 

The validation helper `AssertValidNewVotingItem()` only checks for duplicate voting items, timestamp validity, and snapshot numbers - but completely omits option count validation. [3](#0-2) 

In contrast, the `AddOption()` function correctly enforces the 64-option limit by checking the count BEFORE adding new options. [4](#0-3) 

Similarly, `AddOptions()` enforces the limit by checking AFTER adding (causing revert if exceeded). [5](#0-4) 

The protobuf definition allows unlimited options in the registration input through the `repeated string` field. [6](#0-5) 

An attacker can exploit this by calling `Register()` with an options array containing 65+ elements, bypassing the intended design constraint. Once registered, these voting items cause gas cost attacks on subsequent operations. The `Vote()` function must check if the provided option exists using `Contains()`, which is an O(n) operation that becomes prohibitively expensive with thousands of options. [7](#0-6) 

The test suite confirms that registering with 64 options succeeds, and attempting to add a 65th option via `AddOption()` correctly fails with the validation error. [8](#0-7)  However, no test validates whether `Register()` itself enforces this limit during initial registration.

## Impact Explanation

**High - Protocol Availability Degradation:**

1. **State Bloat Attack:** An attacker can register voting items with thousands or millions of options, causing unbounded blockchain state growth. Each option string is stored permanently in state.

2. **Gas Cost DoS:** Legitimate users attempting to vote on items with excessive options face extremely high gas costs due to the O(n) `Contains()` check operation in `AssertValidVoteInput()`, effectively making these voting items unusable for voting.

3. **Query Performance Degradation:** Any operation retrieving voting items with massive option lists (via `GetVotingItem`) causes significant performance issues for nodes and applications querying the data.

4. **Design Invariant Violation:** The 64-option limit exists as an intentional design constraint enforced by post-registration modification functions. Bypassing it during registration breaks assumptions in integrating systems, frontend applications, and other contracts expecting bounded option lists.

The severity is assessed as **Medium-to-High** because while this doesn't directly steal funds, it enables practical DoS attacks on the voting system's availability and operational integrity.

## Likelihood Explanation

**High Likelihood:**

1. **Public Accessibility:** The `Register()` function is a public RPC method callable by any user without special permissions beyond normal token whitelist requirements.

2. **Zero Preconditions:** The attack requires only standard registration parameters (valid timestamps, whitelisted token symbol) plus an oversized options array.

3. **Trivial Execution:** No complex exploit chain needed - simply construct a `VotingRegisterInput` with 100+ options and call `Register()`.

4. **Low Detection:** The `VotingItemRegistered` event doesn't include option count or the options themselves, making excessive options difficult to detect until someone queries the voting item. [9](#0-8) 

5. **Economic Viability:** While larger protobuf messages increase transaction costs, the attack remains economically viable as the cost is bounded by message size rather than option count impact, while the damage to voting functionality is disproportionate.

## Recommendation

Add option count validation in the `Register()` function before assigning options to the voting item. The validation should be added in `AssertValidNewVotingItem()` or directly in `Register()` to match the enforcement logic in `AddOption()` and `AddOptions()`:

```csharp
// In AssertValidNewVotingItem() or Register()
Assert(input.Options.Count <= VoteContractConstants.MaximumOptionsCount,
    $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
```

This ensures consistent enforcement of the 64-option limit across all option modification paths (registration and post-registration additions).

## Proof of Concept

```csharp
[Fact]
public async Task Register_With_Excessive_Options_Should_Fail()
{
    // Generate 65 options (exceeding the 64 limit)
    var excessiveOptions = Enumerable.Range(0, 65)
        .Select(i => $"Option_{i}")
        .ToList();
    
    var startTime = TimestampHelper.GetUtcNow();
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(10),
        StartTimestamp = startTime,
        Options = { excessiveOptions },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true
    };
    
    // This should fail but currently succeeds, demonstrating the vulnerability
    var result = await VoteContractStub.Register.SendAsync(input);
    
    // Verify the voting item was created with excessive options
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(new VotingRegisterInput
        {
            TotalSnapshotNumber = input.TotalSnapshotNumber,
            EndTimestamp = input.EndTimestamp,
            StartTimestamp = input.StartTimestamp,
            AcceptedCurrency = input.AcceptedCurrency,
            IsLockToken = input.IsLockToken
        }), 
        HashHelper.ComputeFrom(DefaultSender));
    
    var votingItem = await VoteContractStub.GetVotingItem.CallAsync(
        new GetVotingItemInput { VotingItemId = votingItemId });
    
    // Demonstrates the vulnerability: 65 options were stored despite the 64 limit
    votingItem.Options.Count.ShouldBe(65);
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L5-5)
```csharp
    public const int MaximumOptionsCount = 64;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L49-49)
```csharp
            Options = { input.Options },
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L285-286)
```csharp
        Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L320-321)
```csharp
        Assert(votingItem.Options.Count <= VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L381-381)
```csharp
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
```

**File:** protobuf/vote_contract.proto (L99-99)
```text
    repeated string options = 6;
```

**File:** protobuf/vote_contract.proto (L293-319)
```text
message VotingItemRegistered {
    option (aelf.is_event) = true;
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The token symbol which will be accepted.
    string accepted_currency = 2;
    // Whether the vote will lock token.
    bool is_lock_token = 3;
    // The current snapshot number.
    int64 current_snapshot_number = 4;
    // The total number of snapshots of the vote.
    int64 total_snapshot_number = 5;
    // The register time of the voting activity.
    google.protobuf.Timestamp register_timestamp = 6;
    // The start time of the voting.
    google.protobuf.Timestamp start_timestamp = 7;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 8;
    // The start time of current round of the voting.
    google.protobuf.Timestamp current_snapshot_start_timestamp = 9;
    // The sponsor address of the voting activity.
    aelf.Address sponsor = 10;
    // Is quadratic voting.
    bool is_quadratic = 11;
    // Quadratic voting item ticket cost.
    int64 ticket_cost = 12;
}
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L340-352)
```csharp
        // option count exceed 64
        {
            var registerItem = await RegisterVotingItemAsync(100, VoteContractConstant.MaximumOptionsCount, true,
                DefaultSender, 1);
            var newOption = Accounts[VoteContractConstant.MaximumOptionsCount].Address.ToBase58();
            var transactionResult = (await VoteContractStub.AddOption.SendWithExceptionAsync(new AddOptionInput
            {
                Option = newOption,
                VotingItemId = registerItem.VotingItemId
            })).TransactionResult;
            transactionResult.Error.ShouldContain(
                $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
        }
```
