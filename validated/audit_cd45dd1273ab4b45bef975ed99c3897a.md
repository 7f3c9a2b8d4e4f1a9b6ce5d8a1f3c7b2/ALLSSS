# Audit Report

## Title
Off-By-One Error Allows Miner to Produce 9 Continuous Blocks Instead of Intended 8-Block Limit

## Summary
An off-by-one error in the AEDPoS consensus contract's `LatestPubkeyToTinyBlocksCount` mechanism allows malicious miners to produce 9 consecutive blocks instead of the protocol-mandated maximum of 8 blocks. The vulnerability stems from flawed initialization logic combined with an incorrect boundary check (`< 0` instead of `<= 0`) in the validation layer.

## Finding Description

The AEDPoS consensus protocol defines `MaximumTinyBlocksCount = 8` as the maximum continuous blocks any miner can produce [1](#0-0) . This limit is enforced through the `LatestPubkeyToTinyBlocksCount` state tracking mechanism.

The vulnerability exists across three interconnected flaws:

**Flaw 1: First Block Bypass**
When a miner produces their first block, `State.LatestPubkeyToTinyBlocksCount.Value` is `null`. The validation check requires a non-null value to enforce the limit [2](#0-1) , causing the first block to bypass this enforcement entirely.

**Flaw 2: Incorrect Initialization**
After the first block executes, `ResetLatestProviderToTinyBlocksCount` initializes the counter to `MaximumTinyBlocksCount - 1 = 7` [3](#0-2)  instead of 8. This fails to account for the already-produced first block. Each subsequent block decrements this counter [4](#0-3) .

**Flaw 3: Incorrect Boundary Condition**
Both the command validation and header validation use `BlocksCount < 0` as the stopping condition [5](#0-4) [6](#0-5) . This allows block execution when `BlocksCount = 0`, permitting a 9th block before forcing `NextRound` at `BlocksCount = -1`.

**Execution Sequence:**
- Block 1: null state → validation bypassed → executes → sets `BlocksCount = 7`
- Blocks 2-8: `BlocksCount` decrements 7→6→5→4→3→2→1→0 (validation passes: `1,0 < 0` = FALSE)
- Block 9: `BlocksCount = 0` → validation check `0 < 0` = FALSE → **PASSES** → executes → sets `BlocksCount = -1`
- Block 10 attempt: `BlocksCount = -1` → validation check `-1 < 0` = TRUE → **BLOCKED**

While `GetConsensusCommand` includes an `ActualMiningTimes.Count` check that would prevent honest miners from requesting a 9th block [7](#0-6) , the validation layer does NOT check `ActualMiningTimes` [8](#0-7) . A malicious miner can bypass `GetConsensusCommand` by manually crafting a TinyBlock transaction, which will pass validation due to the flawed `LatestPubkeyToTinyBlocksCount` check.

## Impact Explanation

**Severity: Medium**

This vulnerability systematically violates a critical consensus invariant:

1. **Consensus Fairness Violation:** The protocol explicitly defines 8 as the maximum continuous blocks to prevent block monopolization. Allowing 9 blocks gives malicious miners 12.5% additional block production opportunity per sequence.

2. **Financial Advantage:** The extra block enables collection of additional transaction fees and potential MEV (Miner Extractable Value), providing quantifiable unfair advantage.

3. **Protocol-Wide Impact:** Every miner can exploit this equally when producing maximum continuous blocks, making it a systemic fairness degradation affecting all consensus rounds.

4. **Documented Invariant Break:** The `MaximumTinyBlocksCount = 8` constant represents an explicit protocol-level guarantee that is systematically violated.

The severity is Medium rather than Critical because:
- No direct fund loss or theft occurs
- No governance bypass or privilege escalation
- No supply inflation or token security compromise
- All miners can potentially exploit equally (not asymmetric advantage)

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is exploitable but requires deliberate malicious action:

1. **Low Barrier to Entry:** Any miner in the consensus set can exploit this with no special permissions or governance control required.

2. **Requires Malicious Intent:** While the off-by-one error exists in the code, exploitation requires a miner to deliberately:
   - Bypass the advisory `GetConsensusCommand` logic
   - Manually craft a TinyBlock transaction for the 9th block
   - Submit it directly to the network

3. **Validation Layer Failure:** The vulnerability exists because the validation layer (which should be the final enforcement point) has the off-by-one error. A buggy or alternative miner implementation that doesn't properly check `ActualMiningTimes` would also trigger this.

4. **Recurring Opportunity:** Every time any miner reaches maximum continuous blocks, the opportunity exists to exploit this flaw.

The likelihood is not "automatic" as initially claimed - it requires deliberate action or buggy implementation rather than occurring naturally through normal operations.

## Recommendation

Apply a two-part fix to address both the initialization and boundary condition flaws:

**Fix 1: Correct the boundary check**
Change the validation condition from `< 0` to `<= 0`:

In `ContinuousBlocksValidationProvider.cs` (line 19) and `GetConsensusCommand` (line 33):
```csharp
// Change from:
if (latestPubkeyToTinyBlocksCount.BlocksCount < 0)

// To:
if (latestPubkeyToTinyBlocksCount.BlocksCount <= 0)
```

**Fix 2: Correct the initialization**
Initialize to `MaximumTinyBlocksCount` instead of `MaximumTinyBlocksCount - 1`:

In `ResetLatestProviderToTinyBlocksCount` (line 345):
```csharp
// Change from:
BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)

// To:
BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount
```

This ensures the first block counts toward the limit (counter starts at 8, not 7) and blocks are rejected when the counter reaches 0 (not -1).

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanProduce9ContinuousBlocks_ViolatingMaximumLimit()
{
    // Setup: Initialize consensus with MaximumTinyBlocksCount = 8
    // Miner produces first 8 blocks normally through UpdateValue + 7 TinyBlocks
    
    // After 8 blocks: LatestPubkeyToTinyBlocksCount.BlocksCount should be 0
    var latestCount = await AEDPoSContractStub.GetLatestPubkeyToTinyBlocksCount.CallAsync(new Empty());
    latestCount.BlocksCount.ShouldBe(0); // Counter at 0 after 8 blocks
    
    // Malicious action: Manually craft 9th TinyBlock transaction
    var malicious9thBlock = new TinyBlockInput 
    {
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        ProducedBlocks = 9,
        RoundId = currentRound.RoundId,
        RandomNumber = HashHelper.ComputeFrom("malicious")
    };
    
    // BUG: Validation passes because 0 < 0 is FALSE
    var validationResult = await AEDPoSContractStub.ValidateConsensusBeforeExecution.CallAsync(
        CreateHeaderInformation(malicious9thBlock));
    validationResult.Success.ShouldBeTrue(); // VULNERABILITY: Should fail but passes
    
    // Execute the 9th block - should be rejected but isn't
    await AEDPoSContractStub.UpdateTinyBlockInformation.SendAsync(malicious9thBlock);
    
    // Verify: Miner successfully produced 9 blocks instead of maximum 8
    var minerInfo = currentRound.RealTimeMinersInformation[minerPubkey];
    minerInfo.ProducedBlocks.ShouldBe(9); // VULNERABILITY CONFIRMED
    
    // Counter now at -1, blocking 10th block
    latestCount = await AEDPoSContractStub.GetLatestPubkeyToTinyBlocksCount.CallAsync(new Empty());
    latestCount.BlocksCount.ShouldBe(-1); // Only blocks at -1, not at 0
}
```

## Notes

This vulnerability represents a gap between the advisory layer (`GetConsensusCommand`) and the enforcement layer (validation). While honest miner implementations following `GetConsensusCommand` would not trigger this bug, the validation layer must assume adversarial inputs. The off-by-one error in validation allows malicious or buggy miner implementations to violate the documented 8-block maximum, systematically undermining consensus fairness guarantees across the network.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L17-23)
```csharp
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L342-346)
```csharp
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L352-357)
```csharp
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L29-35)
```csharp
        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-62)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```
