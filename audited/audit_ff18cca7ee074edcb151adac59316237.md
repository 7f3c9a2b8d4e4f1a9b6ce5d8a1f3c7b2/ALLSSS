### Title
Block Producer Time Manipulation Allows Expired Seed NFT Token Creation

### Summary
A block producer can manipulate `Context.CurrentBlockTime` by producing blocks with timestamps from their designated time slot while delaying actual block production. This allows bypassing the seed NFT expiration check in `CheckSeedNFT()`, enabling token creation with expired seed NFTs within a ~10-minute window.

### Finding Description

The vulnerability exists in the seed NFT expiration validation at [1](#0-0) 

When creating tokens via `CreateToken()`, the system calls `CheckSeedNFT()` to validate seed NFT expiration. The check at line 130 compares `Context.CurrentBlockTime.Seconds <= expirationTimeLong`. During transaction execution, `Context.CurrentBlockTime` equals the block's header timestamp, not the actual current system time.

**Root Cause - Missing Past Timestamp Validation:**

Block header timestamp validation only rejects blocks with timestamps too far in the FUTURE: [2](#0-1) 

There is NO corresponding check preventing blocks with timestamps in the PAST. The consensus time slot validation only verifies the timestamp falls within the miner's expected time slot: [3](#0-2) 

This validation checks if `latestActualMiningTime < endOfExpectedTimeSlot` but doesn't compare the block timestamp against current system time.

**Execution Path:**

1. Block producer obtains consensus command with `ArrangedMiningTime` within their time slot
2. Producer delays actual block production until after seed NFT expiration
3. Producer creates block using the earlier `ArrangedMiningTime` as timestamp
4. Block validation passes because timestamp is within the time slot window
5. Transaction executes with old `Context.CurrentBlockTime`
6. Expired seed NFT passes expiration check

The network broadcast age limit of 10 minutes provides the exploitation window: [4](#0-3) 

### Impact Explanation

**Direct Impact:**
- Expired seed NFTs can create tokens, undermining the seed NFT expiration mechanism designed to enforce time-limited token creation rights
- Breaks the NFT uniqueness and expiration invariants critical to token supply control
- Allows block producers to bypass time-based authorization controls

**Affected Parties:**
- Token ecosystem relying on seed NFT expiration for scarcity/timing control
- Users who acquired seed NFTs expecting expiration enforcement
- Protocol integrity regarding NFT-based token creation authorization

**Severity Justification:**
This is a Critical severity issue because:
1. Directly violates the seed NFT expiration invariant explicitly checked in the code
2. Affects core token creation authorization mechanism
3. Exploitable by any block producer (not requiring extraordinary privileges)
4. No detection or prevention mechanism exists in current implementation

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a block producer in the AEDPoS consensus (realistic - producers rotate in PoS systems)
- No additional privileges beyond normal block production required

**Attack Complexity:**
- Low - straightforward: obtain consensus command, wait for expiration, produce block with old timestamp
- No complex state manipulation or multi-step transactions required

**Feasibility Conditions:**
- Seed NFT must expire within miner's time slot + ~10 minutes (the network broadcast age limit)
- Attacker must be scheduled as block producer during this window
- With typical time slots (4-8 seconds) and 10-minute broadcast window, exploitation window is substantial

**Detection Constraints:**
- Block appears valid to all nodes - passes all validation checks
- No on-chain evidence of manipulation (timestamp is within valid time slot)
- Cannot be distinguished from legitimate slightly-delayed blocks

**Probability:**
High probability given:
- Block producers rotate regularly in the consensus mechanism
- Attack window of ~10 minutes provides ample opportunity
- No technical barriers beyond being a scheduled producer
- Economic incentive exists for valuable expired seed NFTs

### Recommendation

**Immediate Fix:**
Add past timestamp validation to block validation logic. In `IBlockValidationProvider.ValidateBeforeAttachAsync()`, add a check rejecting blocks with timestamps older than a reasonable threshold (e.g., 1-2 minutes) relative to current system time:

```csharp
var minAllowedBlockTime = TimestampHelper.GetUtcNow() 
    - TimestampHelper.DurationFromMinutes(2);
if (block.Header.Time < minAllowedBlockTime)
{
    Logger.LogDebug("Block timestamp too old");
    return Task.FromResult(false);
}
```

**Additional Hardening:**
1. In consensus validation, compare the new `ActualMiningTime` in the block header against current system time (not just time slot boundaries)
2. Add monitoring/alerting for blocks with timestamps significantly older than received time
3. Consider adding timestamp freshness validation in critical time-sensitive operations like `CheckSeedNFT()`

**Test Cases:**
1. Verify blocks with timestamps > 2 minutes old are rejected
2. Verify seed NFT expiration cannot be bypassed with delayed blocks
3. Test edge cases around time slot boundaries and round transitions

### Proof of Concept

**Initial State:**
- Attacker is scheduled as block producer with time slot 900-904 seconds (4-second window)
- Attacker holds seed NFT with expiration time = 1000 seconds
- Current system time = 900 seconds

**Attack Steps:**

1. At time 900, attacker calls consensus system to get `ArrangedMiningTime`
   - Returns: `ArrangedMiningTime = 902` (within time slot)

2. Attacker does NOT immediately produce block; waits until time = 1100 (100 seconds after expiration)

3. At time 1100, attacker produces block:
   - Block header timestamp = 902 (the old `ArrangedMiningTime`)
   - Includes transaction calling `TokenContract.Create()` with expired seed NFT

4. Block validation at time 1100:
   - `ValidateBeforeAttachAsync`: checks `902 - 1100 = -198`, not > 4 seconds → PASSES
   - `TimeSlotValidationProvider`: checks `902 < 904` → PASSES
   - All validations pass

5. Block execution:
   - `Context.CurrentBlockTime` = 902 (block timestamp)
   - Transaction calls `Create()` → `CheckSeedNFT()`
   - Line 130: `902 <= 1000` → CHECK PASSES
   - Token created successfully with expired seed NFT

**Expected Result:**
Expired seed NFT should be rejected.

**Actual Result:**
Token creation succeeds because `Context.CurrentBlockTime` (902) is before expiration (1000), even though actual current time (1100) is after expiration.

**Success Condition:**
Attacker successfully creates token using seed NFT that expired 100 seconds ago, bypassing the expiration protection mechanism.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L118-131)
```csharp
    private void CheckSeedNFT(string symbolSeed, String symbol)
    {
        Assert(!string.IsNullOrEmpty(symbolSeed), "Seed NFT does not exist.");
        var tokenInfo = GetTokenInfo(symbolSeed);
        Assert(tokenInfo != null, "Seed NFT does not exist.");
        Assert(State.Balances[Context.Sender][symbolSeed] > 0, "Seed NFT balance is not enough.");
        Assert(tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.SeedOwnedSymbolExternalInfoKey, out var ownedSymbol) && ownedSymbol == symbol,
            "Invalid OwnedSymbol.");
        Assert(tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                   out var expirationTime)
               && long.TryParse(expirationTime, out var expirationTimeLong) &&
               Context.CurrentBlockTime.Seconds <= expirationTimeLong, "OwnedSymbol is expired.");
    }
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L133-139)
```csharp
        if (block.Header.Height != AElfConstants.GenesisBlockHeight &&
            block.Header.Time.ToDateTime() - TimestampHelper.GetUtcNow().ToDateTime() >
            KernelConstants.AllowedFutureBlockTimeSpan.ToTimeSpan())
        {
            Logger.LogDebug("Future block received {Block}, {BlockTime}", block, block.Header.Time.ToDateTime());
            return Task.FromResult(false);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** src/AElf.OS.Core/Network/NetworkConstants.cs (L15-15)
```csharp
    public const int DefaultMaxBlockAgeToBroadcastInMinutes = 10;
```
