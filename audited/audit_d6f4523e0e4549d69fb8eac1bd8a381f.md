# Audit Report

## Title
AddOptions() Fails to Validate Duplicate Options Within Same Batch Submission

## Summary
The `AddOptions()` function in the Vote contract does not detect duplicate options within a single batch submission. The validation logic only checks each option against the current stored state, not against other options in the same input array. This allows voting item sponsors to add duplicate options, violating the uniqueness invariant and enabling option slot exhaustion attacks that compromise voting governance integrity. [1](#0-0) 

## Finding Description

The vulnerability exists in the `AddOptions()` function's validation logic. The function iterates through each option in `input.Options` and validates it using `AssertOption()`: [2](#0-1) 

However, `AssertOption()` only validates that each option doesn't exist in the current state (`votingItem.Options`), not against other options in the same batch: [3](#0-2) 

The critical issue is that the validation at line 295 checks `!votingItem.Options.Contains(option)` which only verifies the option isn't already in storage. Since the validation occurs in a loop **before** any additions are made, all options in the input array are checked against the same pre-existing state. After all validations pass, the entire `input.Options` array is added via `AddRange()`: [4](#0-3) 

**Execution Path:**
1. Sponsor calls `AddOptions()` with `input.Options = ["A", "A"]`
2. First iteration: `AssertOption()` checks if "A" exists in `votingItem.Options` → passes (not in state)
3. Second iteration: `AssertOption()` checks if "A" exists in `votingItem.Options` → passes (still not in state, since nothing has been added yet)
4. Line 319: `votingItem.Options.AddRange(input.Options)` adds both "A" entries
5. Result: `votingItem.Options` now contains duplicate "A" values

This breaks the uniqueness guarantee implied by the "Option already exists" assertion message and violates the fundamental assumption that voting options should be distinct.

## Impact Explanation

**Primary Impacts:**

1. **Option Slot Exhaustion**: The maximum options count is enforced after addition, with a limit defined as: [5](#0-4) 
   
   With `MaximumOptionsCount = 64`, a malicious sponsor could add 32 unique options twice, consuming all 64 slots with only 32 distinct choices. This prevents legitimate options from being added later and violates the intent of the limit. [6](#0-5) 

2. **Governance Integrity Confusion**: In governance contexts where voting items represent critical decisions, duplicate options create confusion that can be weaponized to:
   - Mislead voters about available choices
   - Manipulate perceived voting distributions
   - Create UI/frontend display issues
   - Introduce ambiguity in voting outcomes

3. **Incomplete Option Removal**: The `RemoveOption()` function uses the standard C# `Remove()` method: [7](#0-6) 
   
   This only removes the first occurrence of a duplicate, leaving remaining copies in place and requiring multiple transactions to fully clean up.

**Severity**: Medium - While vote counting remains correct (the voting results use a map structure that handles duplicates correctly), the operational impact on voting governance integrity and the ability to bypass option slot limits constitute a significant flaw in the voting system's state consistency.

## Likelihood Explanation

**Exploitability: HIGH**

- **Reachable Entry Point**: `AddOptions()` is a public method with only sponsor authorization required
- **Attacker Capabilities**: Only requires being the sponsor of a voting item (a legitimate role that any user can obtain by creating a voting item)
- **Attack Complexity**: Trivial - simply pass an array with duplicate strings: `new AddOptionsInput { VotingItemId = id, Options = { "A", "A" } }`
- **Preconditions**: None beyond having sponsor permissions on a voting item
- **Detection**: Difficult to detect proactively without explicit validation; requires inspection of the `votingItem.Options` list after the fact
- **Economic Cost**: Minimal - only standard transaction fees

**Feasibility**: The exploit requires no special privileges beyond normal sponsor capabilities. Any sponsor, whether acting maliciously or making an honest mistake, can introduce duplicates. The existing test suite confirms this scenario is not validated: [8](#0-7) 

The tests verify permission checks and successful addition of distinct options, but do not test duplicate detection within a single batch submission.

## Recommendation

Add validation to detect duplicates within the input array before adding options. The fix should check for duplicates in the `input.Options` collection itself:

```csharp
public override Empty AddOptions(AddOptionsInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // Check for duplicates within the input array
    var uniqueOptions = new HashSet<string>();
    foreach (var option in input.Options)
    {
        Assert(uniqueOptions.Add(option), "Duplicate options in input are not allowed.");
        AssertOption(votingItem, option);
    }
    
    votingItem.Options.AddRange(input.Options);
    Assert(votingItem.Options.Count <= VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Alternatively, use LINQ to detect duplicates before validation:

```csharp
public override Empty AddOptions(AddOptionsInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    Assert(input.Options.Count == input.Options.Distinct().Count(), 
        "Duplicate options in input are not allowed.");
    
    foreach (var option in input.Options) AssertOption(votingItem, option);
    votingItem.Options.AddRange(input.Options);
    Assert(votingItem.Options.Count <= VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task VoteContract_AddOptions_WithDuplicates_Test()
{
    // Register a voting item with initial options
    var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);
    
    // Attempt to add duplicate options in the same batch
    var transactionResult = await VoteContractStub.AddOptions.SendAsync(new AddOptionsInput
    {
        VotingItemId = registerItem.VotingItemId,
        Options =
        {
            "Option_A",
            "Option_A"  // Duplicate
        }
    });
    
    // Transaction should succeed (demonstrating the vulnerability)
    transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify that duplicates were actually added
    var votingItem = await GetVoteItem(registerItem.VotingItemId);
    
    // Count should be 5: 3 initial + 2 added (including duplicate)
    votingItem.Options.Count.ShouldBe(5);
    
    // Verify duplicate exists by counting occurrences
    var optionACount = votingItem.Options.Count(o => o == "Option_A");
    optionACount.ShouldBe(2); // Proves duplicate was added
    
    // This demonstrates the vulnerability: duplicates are not detected
}
```

This test demonstrates that the contract allows duplicate options to be added in a single batch, violating the uniqueness invariant and confirming the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L292-296)
```csharp
    private void AssertOption(VotingItem votingItem, string option)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(!votingItem.Options.Contains(option), "Option already exists.");
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L309-309)
```csharp
        votingItem.Options.Remove(input.Option);
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

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L5-5)
```csharp
    public const int MaximumOptionsCount = 64;
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L453-506)
```csharp
    public async Task VoteContract_AddOptions_Test()
    {
        //without permission
        {
            var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);
            var otherUser = Accounts[10].KeyPair;
            var transactionResult = (await GetVoteContractTester(otherUser).AddOptions.SendWithExceptionAsync(
                new AddOptionsInput
                {
                    VotingItemId = registerItem.VotingItemId,
                    Options =
                    {
                        Accounts[0].Address.ToBase58(),
                        Accounts[1].Address.ToBase58()
                    }
                })).TransactionResult;

            transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            transactionResult.Error.Contains("Only sponsor can update options").ShouldBeTrue();
        }
        //voteItem does not exist
        {
            var itemId = HashHelper.ComputeFrom("hash");
            var transactionResult = (await VoteContractStub.AddOptions.SendWithExceptionAsync(new AddOptionsInput
            {
                VotingItemId = itemId,
                Options =
                {
                    Accounts[0].Address.ToBase58()
                }
            })).TransactionResult;

            transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            transactionResult.Error.Contains("Voting item not found.").ShouldBeTrue();
        }
        //success
        {
            var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);
            var transactionResult = (await VoteContractStub.AddOptions.SendAsync(new AddOptionsInput
            {
                VotingItemId = registerItem.VotingItemId,
                Options =
                {
                    Accounts[3].Address.ToBase58(),
                    Accounts[4].Address.ToBase58()
                }
            })).TransactionResult;

            transactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var votingItem = await GetVoteItem(registerItem.VotingItemId);
            votingItem.Options.Count.ShouldBe(5);
        }
    }
```
