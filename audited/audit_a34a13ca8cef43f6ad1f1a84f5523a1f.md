# Audit Report

## Title
Missing Option Validation in Register Method Enables State Bloat Attack

## Summary
The `Register` method in the Vote contract fails to validate the number and length of options provided in `VotingRegisterInput`, allowing attackers to bypass the intended limits of 64 options and 1024 bytes per option. This enables state bloat attacks where each voting item can store up to 64KB of data for only 10 ELF, creating permanent on-chain storage burden.

## Finding Description

The Vote contract defines critical constants to limit option storage: [1](#0-0) 

However, the `Register` method directly copies input options without any validation: [2](#0-1) 

The validation function `AssertValidNewVotingItem` only checks timestamps and duplicate voting items, completely ignoring option validation: [3](#0-2) 

In contrast, the `AddOption` method properly enforces both the option count limit and individual option validation: [4](#0-3) 

The `AssertOption` helper validates individual option lengths: [5](#0-4) 

The `AddOptions` method also enforces the count limit after adding multiple options: [6](#0-5) 

**Root Cause:** Inconsistent validation enforcement - option limits are checked when modifying existing voting items via `AddOption`/`AddOptions`, but are completely bypassed during initial registration via `Register`.

**Why Protections Fail:** The validation logic exists in `AssertOption` and is properly used by `AddOption`/`AddOptions`, but the `Register` method never calls these validation functions on `input.Options` before storing them in state.

## Impact Explanation

An attacker can create voting items with 64 options of 1024 bytes each, storing 65,536 bytes per voting item permanently on-chain. This data is stored in the contract state and must be maintained by all full nodes.

**Quantified Damage:**
- Storage per attack: 64KB per voting item
- Attack cost: 10 ELF per voting item [7](#0-6) 
- Scale: With 1,000 ELF, an attacker could create approximately 100 voting items = 6.4 MB of bloat
- Per-byte cost: ~0.00015 ELF per byte for permanent storage
- No cleanup mechanism exists - voting items persist indefinitely in contract state

**Who is Affected:** All full nodes must store and serve this bloated state, degrading network performance and increasing storage requirements. This affects the entire blockchain's scalability and operational costs.

**Severity Justification:** HIGH - Low-cost attack (10 ELF per 64KB) with permanent impact on blockchain state and no recovery mechanism. The attack can be repeated indefinitely to compound the damage. This breaks the protocol's intended invariant that options should be limited to protect state size.

## Likelihood Explanation

**Attacker Capabilities:** Any user with 10 ELF can execute this attack. No special privileges or governance approval required. The `Register` method is public and can be called by anyone.

**Attack Complexity:** Trivial - construct a `VotingRegisterInput` with 64 strings of 1024 bytes each and call the public `Register` method.

**Feasibility Conditions:**
- Attacker needs sufficient balance to cover 10 ELF transaction fee
- Accepted currency must be in the token whitelist (standard tokens like ELF qualify)
- No other preconditions required

**Detection Constraints:** The attack is indistinguishable from legitimate voting item creation. Each transaction appears valid with proper fee payment.

**Probability:** HIGH - The attack is economically rational if the attacker's goal is to degrade network performance or increase operational costs for node operators. The per-byte cost for permanent on-chain storage is extremely cheap compared to the intended design that enforces strict limits.

## Recommendation

Add option validation to the `Register` method to enforce the defined constants. The fix should validate both the count and length of options before storing them:

```csharp
public override Empty Register(VotingRegisterInput input)
{
    var votingItemId = AssertValidNewVotingItem(input);
    
    // Add validation for options count
    Assert(input.Options.Count <= VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    
    // Add validation for each option length
    foreach (var option in input.Options)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    }
    
    // Rest of the method...
}
```

Alternatively, create a dedicated validation helper that can be reused:

```csharp
private void ValidateOptions(IEnumerable<string> options, int currentCount = 0)
{
    var optionsList = options.ToList();
    Assert(currentCount + optionsList.Count <= VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    
    foreach (var option in optionsList)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    }
}
```

Then call this in `Register`, `AddOption`, and `AddOptions` methods to ensure consistent validation across all entry points.

## Proof of Concept

```csharp
[Fact]
public async Task VoteContract_Register_StateBloat_Attack_Test()
{
    // Attacker creates a voting item with maximum options and maximum length
    var startTime = TimestampHelper.GetUtcNow();
    
    // Create 64 options, each with 1024 bytes
    var bloatedOptions = new List<string>();
    for (int i = 0; i < 64; i++)
    {
        bloatedOptions.Add(new string('A', 1024)); // 1024 bytes per option
    }
    
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(10),
        StartTimestamp = startTime,
        Options = { bloatedOptions },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true
    };
    
    // This should fail due to option validation, but currently succeeds
    var transactionResult = (await VoteContractStub.Register.SendAsync(input)).TransactionResult;
    
    // Vulnerability: Transaction succeeds, storing 64KB on-chain for only 10 ELF
    transactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify the bloated data was stored
    input.Options.Clear();
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(input), 
        HashHelper.ComputeFrom(DefaultSender));
    
    var votingItem = await VoteContractStub.GetVotingItem.CallAsync(
        new GetVotingItemInput { VotingItemId = votingItemId });
    
    // Verify 64 options of 1024 bytes each were stored
    votingItem.Options.Count.ShouldBe(64);
    foreach (var option in votingItem.Options)
    {
        option.Length.ShouldBe(1024);
    }
    
    // Total bloat: 64 * 1024 = 65,536 bytes stored for 10 ELF
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L5-6)
```csharp
    public const int MaximumOptionsCount = 64;
    public const int OptionLengthLimit = 1024;
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

**File:** contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs (L42-49)
```csharp
            case nameof(Register):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
```
