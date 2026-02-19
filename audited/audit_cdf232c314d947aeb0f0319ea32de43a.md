### Title
Unreasonably High ImpliedIrreversibleBlockHeight Causes Consensus DoS via Arithmetic Overflow

### Summary
A malicious miner can submit an UpdateValueInput with an arbitrarily high ImpliedIrreversibleBlockHeight (e.g., exceeding current block height by trillions) that bypasses validation and gets stored in the consensus contract state. When GetMaximumBlocksCount attempts to calculate the distance between current height and this bogus LIB height, the SafeMath.Sub operation throws an OverflowException, permanently halting all consensus operations and blocking future block production.

### Finding Description

**Root Cause Locations:**

The `Deconstruct()` function selects a libHeight without validating it's reasonable: [1](#0-0) 

The `ProcessUpdateValue` method accepts ImpliedIrreversibleBlockHeight from user input without validation: [2](#0-1) 

**Attack Path:**

1. A malicious miner submits UpdateValue transaction with ImpliedIrreversibleBlockHeight set to an extremely high value (e.g., 999999999999).

2. ProcessUpdateValue stores this value without checking if it exceeds Context.CurrentHeight: [2](#0-1) 

3. The LibInformationValidationProvider only validates non-decreasing values, not upper bounds: [3](#0-2) 

4. LastIrreversibleBlockHeightCalculator.Deconstruct() calculates LIB from miners' implied heights: [4](#0-3) 

5. The bogus value gets selected at the 1/3 consensus threshold position without validation: [1](#0-0) 

6. The contract state is corrupted with the unreasonably high value: [5](#0-4) 

7. State is persisted: [6](#0-5) 

**Why Existing Protections Fail:**

While IrreversibleBlockFoundLogEventProcessor validates that blocks exist before setting chain LIB: [7](#0-6) 

This blockchain-level validation occurs AFTER the contract state has already been corrupted. The contract's ConfirmedIrreversibleBlockHeight is updated at line 279 and persisted at line 284 before the event is processed.

**Critical Failure Point:**

Every subsequent consensus transaction calls GetMaximumBlocksCount: [8](#0-7) 

GetMaximumBlocksCount reads the corrupted ConfirmedIrreversibleBlockHeight: [9](#0-8) 

Then attempts to calculate distance using checked arithmetic: [10](#0-9) 

The SafeMath.Sub method uses checked arithmetic that throws OverflowException on underflow: [11](#0-10) 

### Impact Explanation

**Concrete Harm:**
- **Complete Blockchain DoS**: All consensus operations permanently fail due to OverflowException in GetMaximumBlocksCount
- **Block Production Halted**: No new blocks can be produced since every consensus transaction crashes
- **Irreversible Damage**: The corrupted state persists and cannot self-correct since line 272's check `if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)` prevents any future legitimate updates from overwriting the bogus value
- **Network Unavailability**: The entire blockchain becomes non-functional until a hard fork or emergency contract upgrade

**Who Is Affected:**
- All network participants (users, validators, applications)
- All pending transactions become permanently stuck
- Cross-chain operations depending on this chain halt
- Token transfers, governance, and all other contract operations cease

**Severity Justification:**
CRITICAL - This is a complete availability attack requiring only a single malicious miner to execute, causing permanent network-wide DoS with no automatic recovery mechanism.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires miner privileges (must be in current or previous round's miner list)
- Can modify client to send arbitrary UpdateValueInput values
- Only ONE miner needs to provide the bogus value if it lands at the 1/3 consensus position

**Attack Complexity:**
- LOW: Single transaction with modified ImpliedIrreversibleBlockHeight parameter
- No need for coordination with other miners
- No timing requirements or race conditions
- Deterministic outcome once executed

**Feasibility Conditions:**
- Attacker must be an active miner (realistic - miners are elected/staked participants)
- PreCheck only validates miner is in miner list: [12](#0-11) 

**Detection/Operational Constraints:**
- Attack succeeds silently on first transaction (state corrupted)
- Damage manifests on NEXT block when GetMaximumBlocksCount is called
- No monitoring could prevent the attack since validation happens after state update
- Recovery requires emergency intervention (contract upgrade or chain fork)

**Probability Reasoning:**
HIGH - Any miner can execute this attack at will with a single malicious transaction. The normal code path for setting ImpliedIrreversibleBlockHeight uses Context.CurrentHeight: [13](#0-12) 

But miners can bypass this by directly crafting UpdateValueInput with arbitrary values.

### Recommendation

**Immediate Fix - Add Upper Bound Validation:**

In ProcessUpdateValue, add validation before line 248:

```csharp
// Validate ImpliedIrreversibleBlockHeight is reasonable
Assert(updateValueInput.ImpliedIrreversibleBlockHeight <= Context.CurrentHeight,
    "ImpliedIrreversibleBlockHeight cannot exceed current block height.");
```

Location to add check: [14](#0-13) 

**Additional Defense - Validate in Deconstruct:**

In LastIrreversibleBlockHeightCalculator.Deconstruct(), add validation before line 32:

```csharp
// Filter out any heights that exceed current round's reasonable bounds
var currentHeight = _currentRound.RealTimeMinersInformation.Values
    .SelectMany(m => m.ActualMiningTimes)
    .Select(t => /* derive height from mining time */)
    .DefaultIfEmpty(0)
    .Max();
    
impliedIrreversibleHeights = impliedIrreversibleHeights
    .Where(h => h <= currentHeight)
    .ToList();

if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
{
    libHeight = 0;
    return;
}
```

Location: [15](#0-14) 

**Enhance LibInformationValidationProvider:**

Add upper bound check to the validation provider: [3](#0-2) 

**Test Cases to Add:**
1. Test UpdateValue with ImpliedIrreversibleBlockHeight > Context.CurrentHeight (should fail)
2. Test UpdateValue with ImpliedIrreversibleBlockHeight = Context.CurrentHeight + 1000000 (should fail)
3. Test that GetMaximumBlocksCount doesn't throw when ConfirmedIrreversibleBlockHeight is set
4. Test LIB calculation filters out unreasonable values even if they bypass validation

### Proof of Concept

**Required Initial State:**
- Active AEDPoS consensus running
- Attacker is an elected miner in current round
- Current block height = 1000

**Attack Steps:**

1. **Craft Malicious Transaction:**
   - Attacker prepares UpdateValue transaction
   - Sets ImpliedIrreversibleBlockHeight = 999999999999 (far exceeds current height)
   - Uses legitimate values for other fields (Signature, OutValue, etc.)

2. **Submit Transaction:**
   - Attacker's miner client submits the malicious UpdateValue
   - Transaction passes PreCheck (attacker is valid miner)
   - Line 248 stores bogus value: `minerInRound.ImpliedIrreversibleBlockHeight = 999999999999`

3. **State Corruption:**
   - LastIrreversibleBlockHeightCalculator runs (lines 268-269)
   - Deconstruct selects value at 1/3 position: libHeight = 999999999999
   - Line 279 corrupts state: `currentRound.ConfirmedIrreversibleBlockHeight = 999999999999`
   - Line 284 persists corrupted state to storage

4. **DoS Triggered:**
   - Next miner attempts to produce block
   - ProcessConsensusInformation line 68 calls GetMaximumBlocksCount()
   - Line 26 reads: `libBlockHeight = 999999999999`
   - Line 27 reads: `currentHeight = 1001`
   - Line 63 attempts: `currentHeight.Sub(libBlockHeight)` = `1001 - 999999999999`
   - SafeMath.Sub throws OverflowException (checked arithmetic)
   - Transaction fails, no block produced

**Expected vs Actual Result:**
- **Expected**: ImpliedIrreversibleBlockHeight rejected as invalid, consensus continues normally
- **Actual**: Invalid value accepted, state corrupted, subsequent consensus operations permanently fail with OverflowException

**Success Condition:**
Attack succeeds when:
1. First malicious UpdateValue transaction completes successfully
2. Next consensus transaction fails with OverflowException
3. All future block production attempts fail
4. Blockchain is permanently halted until emergency intervention

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-68)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-269)
```csharp
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L279-279)
```csharp
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L63-65)
```csharp
            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L25-26)
```csharp
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L63-63)
```csharp
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```
