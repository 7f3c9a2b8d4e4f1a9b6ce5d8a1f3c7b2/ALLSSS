### Title
Tiny Block Validation Bypassed Due to Ineffective Round Recovery and Hash Comparison

### Summary
The `GetTinyBlockRound()` function creates minimal round data for tiny block headers, but the validation in `ValidateConsensusAfterExecution` is fundamentally broken because it compares an object to itself after recovery, causing validation to always pass regardless of data correctness. Additionally, critical fields (`ProducedBlocks`, `ProducedTinyBlocks`) included in the header are neither validated nor used, allowing blocks with incorrect consensus data to be accepted.

### Finding Description

The `GetTinyBlockRound()` function creates a simplified Round object containing only 5 fields per miner: [1](#0-0) 

During validation after execution, the `RecoverFromTinyBlock()` method only recovers 2 of these fields (`ImpliedIrreversibleBlockHeight` and `ActualMiningTimes`), completely ignoring `ProducedBlocks` and `ProducedTinyBlocks`: [2](#0-1) 

The critical flaw is in `ValidateConsensusAfterExecution`, where the validation logic is fundamentally broken: [3](#0-2) 

The issue occurs at lines 94-97: `RecoverFromTinyBlock()` modifies `currentRound` in-place and returns `this` (the same object reference). This means `headerInformation.Round` and `currentRound` become the same object reference. The subsequent hash comparison at line 100 compares the object to itself, which always passes.

Furthermore, `ProcessTinyBlock()` completely ignores the `ProducedBlocks` value from the transaction input and simply increments by 1: [4](#0-3) 

The hash calculation excludes `ActualMiningTimes` but includes `ProducedBlocks` and `ProducedTinyBlocks`: [5](#0-4) 

### Impact Explanation

**Consensus Integrity Violation:**
- Blocks with arbitrarily incorrect `ProducedBlocks` and `ProducedTinyBlocks` values in headers are accepted without detection
- The validation that should ensure header consistency with state changes is completely bypassed
- This violates the critical invariant: "Correct round transitions and time-slot validation, miner schedule integrity"

**Concrete Harm:**
1. **Block Production Manipulation**: Malicious miners can include false block production counts in block headers without detection, potentially corrupting consensus statistics and monitoring systems
2. **Validation Framework Compromise**: The broken validation means any future code depending on post-execution validation for tiny blocks will be ineffective
3. **Protocol Trust Erosion**: Other nodes receive blocks with unvalidated consensus data, breaking assumptions about header data integrity

**Who Is Affected:**
- All consensus participants receiving and validating tiny blocks
- Monitoring systems relying on accurate consensus data
- Future protocol upgrades that assume validation integrity

### Likelihood Explanation

**Attacker Capabilities:**
- Any miner with permission to produce tiny blocks
- No special privileges beyond normal mining operations required

**Attack Complexity:**
- LOW: The validation always passes due to the reference comparison bug
- Attacker simply needs to produce a tiny block with modified `ProducedBlocks`/`ProducedTinyBlocks` values in the header

**Feasibility:**
- The bug is in production code and triggers on every tiny block validation
- No special timing or race conditions required
- The validation is called by the standard block validation pipeline

**Detection Constraints:**
- The validation silently passes with no error logs
- Incorrect header data would not trigger any alerts
- State remains correct (due to `ProcessTinyBlock` ignoring input), making the issue harder to detect

**Probability:**
- HIGH: The validation bug affects every tiny block processed
- The broken comparison (object to itself) guarantees bypass in 100% of cases

### Recommendation

**Immediate Fixes:**

1. **Fix the RecoverFromTinyBlock pattern** - Create a new Round object instead of modifying in place:
```csharp
public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
{
    var recoveredRound = this.Clone(); // Create a copy
    if (!recoveredRound.RealTimeMinersInformation.ContainsKey(pubkey) ||
        !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
        return recoveredRound;

    var minerInRound = recoveredRound.RealTimeMinersInformation[pubkey];
    var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
    
    // Validate and update fields
    minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
    minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
    minerInRound.ProducedBlocks = providedInformation.ProducedBlocks; // Actually use header value
    minerInRound.ProducedTinyBlocks = providedInformation.ProducedTinyBlocks;
    
    return recoveredRound;
}
```

2. **Validate ProducedBlocks in ProcessTinyBlock**:
```csharp
private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    
    // Validate provided value matches expected increment
    Assert(tinyBlockInput.ProducedBlocks == minerInRound.ProducedBlocks.Add(1), 
           "ProducedBlocks mismatch in TinyBlockInput");
    
    minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
    minerInRound.ProducedBlocks = tinyBlockInput.ProducedBlocks; // Use validated value
    minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
    
    Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
}
```

3. **Add test coverage** for validation with incorrect header values to prevent regression

### Proof of Concept

**Initial State:**
- Consensus system initialized with multiple miners
- Current round active with miner producing tiny blocks

**Attack Steps:**

1. Malicious miner prepares to produce a tiny block
2. In `GetConsensusExtraData`, before calling `GetTinyBlockRound`, the attacker modifies the local round copy:
   - Sets `ProducedBlocks = 9999` (false value)
   - Sets `ProducedTinyBlocks = 9999`
3. Calls `GetTinyBlockRound` which includes these false values in the header
4. Generates `TinyBlockInput` transaction with `ProducedBlocks = 9999`
5. Block is broadcast with header containing false consensus data

**Validation Flow:**

1. `ValidateBeforeExecution`: 
   - Calls `RecoverFromTinyBlock` (lines 49-50 in Validation.cs)
   - Only updates `ImpliedIrreversibleBlockHeight` and `ActualMiningTimes`
   - Ignores false `ProducedBlocks` values
   - Passes ✓

2. `ProcessTinyBlock`:
   - Ignores `tinyBlockInput.ProducedBlocks` value (line 305)
   - Increments state by 1 correctly
   - State shows correct value, header has false value
   - Executes ✓

3. `ValidateConsensusAfterExecution`:
   - Loads `currentRound` from state (line 87)
   - Calls `currentRound.RecoverFromTinyBlock()` (lines 94-97)
   - Assigns return value (same object) to `headerInformation.Round`
   - Compares `headerInformation.Round.GetHash() != currentRound.GetHash()` (line 100)
   - Both are same object → hashes identical → validation passes ✓

**Expected Result:**
Validation should fail because header `ProducedBlocks` (9999) doesn't match state `ProducedBlocks` (incremented by 1)

**Actual Result:**
Block is accepted with incorrect consensus data in header. Validation always passes due to self-comparison bug.

**Success Condition:**
Block with `ProducedBlocks = 9999` in header accepted while state shows actual correct value, demonstrating validation bypass.

### Notes

The minimal data assumption in tiny block rounds is insufficient not because missing fields cause validation to fail, but because the included fields are not properly validated and the validation mechanism itself is fundamentally broken. The `ProducedBlocks` and `ProducedTinyBlocks` fields are included in the header but serve no validation purpose, while the post-execution validation compares an object to itself, making it impossible to detect any discrepancies. This represents a significant gap in consensus integrity verification that should be addressed to maintain protocol security.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-82)
```csharp
    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = minerInRound.Pubkey,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight
                }
            }
        };

        foreach (var otherPubkey in RealTimeMinersInformation.Keys.Except(new List<string> { pubkey }))
            round.RealTimeMinersInformation.Add(otherPubkey, new MinerInRound());

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-47)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```
