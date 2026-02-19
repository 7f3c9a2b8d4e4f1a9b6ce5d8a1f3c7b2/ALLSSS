### Title
Missing Option Length Validation in Vote Contract Registration Allows Permanent Storage Bloat

### Summary
The `Register()` function in the Vote contract does not validate the length of individual option strings when creating a voting item, while `AddOption()`, `AddOptions()`, `RemoveOption()`, and `Vote()` all enforce the 1024-character limit. This allows attackers to register voting items with arbitrarily long option strings, causing blockchain storage bloat that cannot be cleaned up due to the validation in `RemoveOption()` preventing removal of oversized options.

### Finding Description

The vulnerability exists in the `Register()` function where options are directly copied from input without length validation: [1](#0-0) 

The `AssertValidNewVotingItem()` helper function called during registration only validates timestamps and voting item uniqueness, but does not check option lengths: [2](#0-1) 

In contrast, the `AddOption()` function enforces the length limit through `AssertOption()`: [3](#0-2) 

The `AssertOption()` validation function checks the 1024-character limit defined in constants: [4](#0-3) [5](#0-4) 

The `AddOptions()` function similarly validates each option through the same validation path: [6](#0-5) 

The `RemoveOption()` function also enforces the length limit, which creates a permanent lock situation where oversized options cannot be removed: [7](#0-6) 

The `Vote()` function also validates option length, preventing votes on oversized options: [8](#0-7) 

### Impact Explanation

**Storage Bloat**: An attacker can register voting items with option strings containing millions of characters, consuming excessive blockchain storage. Each character stored permanently increases the state size.

**Permanent Pollution**: Once registered, these oversized options cannot be removed because `RemoveOption()` validates that the input option length must be ≤ 1024 characters before checking if the option exists. To remove an option, the sponsor must provide the exact string, but if the string exceeds 1024 characters, the removal transaction will fail at the length check.

**Useless Voting Items**: The voting items become non-functional because:
- Users cannot vote for the oversized options (Vote() validates length)
- The sponsor cannot clean up the options (RemoveOption() validates length)
- The voting item persists in storage but serves no purpose

**Cost to Network**: This is a griefing attack vector where malicious actors can bloat the blockchain state at relatively low cost (only transaction fees), affecting all node operators who must store this data permanently.

### Likelihood Explanation

**Reachable Entry Point**: The `Register()` function is a public method callable by any user: [9](#0-8) 

**Low Preconditions**: The only requirement is that the accepted currency token must be in the whitelist: [10](#0-9) 

For common tokens like the native token, this requirement is trivially satisfied.

**Simple Execution**: An attacker simply needs to:
1. Prepare a `VotingRegisterInput` with valid timestamps and accepted currency
2. Include one or more option strings exceeding 1024 characters (e.g., millions of 'A' characters)
3. Call `Register()` 
4. Pay only the standard transaction fee

**No Detection**: There is no check that would prevent or detect this attack before the oversized options are permanently stored.

### Recommendation

Add option length validation in the `Register()` function. Modify `AssertValidNewVotingItem()` to validate all option lengths:

```csharp
private Hash AssertValidNewVotingItem(VotingRegisterInput input)
{
    // Use input without options and sender's address to calculate voting item id.
    var votingItemId = input.GetHash(Context.Sender);

    Assert(State.VotingItems[votingItemId] == null, "Voting item already exists.");

    // Validate option lengths
    foreach (var option in input.Options)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    }

    // total snapshot number can't be 0. At least one epoch is required.
    if (input.TotalSnapshotNumber == 0) input.TotalSnapshotNumber = 1;

    Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");

    Context.LogDebug(() => $"Voting item created by {Context.Sender}: {votingItemId.ToHex()}");

    return votingItemId;
}
```

Additionally, add a regression test case:

```csharp
[Fact]
public async Task Register_With_Oversized_Option_Should_Fail()
{
    var startTime = TimestampHelper.GetUtcNow();
    var oversizedOption = new StringBuilder().Append('a', VoteContractConstants.OptionLengthLimit + 1);
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(10),
        StartTimestamp = startTime,
        Options = { oversizedOption.ToString() },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true
    };
    var transactionResult = (await VoteContractStub.Register.SendWithExceptionAsync(input)).TransactionResult;
    transactionResult.Error.ShouldContain("Invalid input.");
}
```

### Proof of Concept

**Initial State**: 
- A valid token (e.g., native token) is in the whitelist
- Attacker has sufficient balance for transaction fees

**Attack Steps**:

1. Attacker prepares a malicious registration input:
```csharp
var startTime = TimestampHelper.GetUtcNow();
var maliciousOption = new string('A', 1000000); // 1 million characters
var input = new VotingRegisterInput
{
    TotalSnapshotNumber = 1,
    EndTimestamp = startTime.AddDays(10),
    StartTimestamp = startTime,
    Options = { maliciousOption },
    AcceptedCurrency = "ELF", // or other whitelisted token
    IsLockToken = true
};
```

2. Attacker calls `Register()` with the malicious input
3. Transaction succeeds, storing the 1-million-character option string

**Expected vs Actual Result**:
- **Expected**: Transaction should fail with "Invalid input." error
- **Actual**: Transaction succeeds, option is permanently stored

**Verification**:
- Query the voting item to confirm the oversized option exists
- Attempt to remove the option using `RemoveOption()` - fails with "Invalid input."
- Attempt to vote for the option using `Vote()` - fails with "Invalid input."
- The malicious option remains permanently in storage, cannot be cleaned up

**Success Condition**: The attack succeeds when the oversized option is stored and cannot be removed, causing permanent storage bloat.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-22)
```csharp
    public override Empty Register(VotingRegisterInput input)
    {
        var votingItemId = AssertValidNewVotingItem(input);
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L49-49)
```csharp
            Options = { input.Options },
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L292-296)
```csharp
    private void AssertOption(VotingItem votingItem, string option)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(!votingItem.Options.Contains(option), "Option already exists.");
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L303-312)
```csharp
    public override Empty RemoveOption(RemoveOptionInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
        votingItem.Options.Remove(input.Option);
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-401)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
        else
        {
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }

        return votingItem;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L6-6)
```csharp
    public const int OptionLengthLimit = 1024;
```
