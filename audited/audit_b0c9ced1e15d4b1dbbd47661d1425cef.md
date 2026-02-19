### Title
Consensus Behavior Misrepresentation Allows Bypass of Critical Validators

### Summary
Miners can claim `TinyBlock` consensus behavior when they should execute `UpdateValue`, bypassing `UpdateValueValidationProvider` and `LibInformationValidationProvider`. This allows miners to skip publishing consensus information (OutValue/Signature) and evade LIB height validation for up to 8 consecutive blocks, compromising consensus integrity and randomness generation.

### Finding Description

The validation provider registration in `ValidateBeforeExecution` is based on the self-attested `extraData.Behaviour` field without verifying it matches the expected behavior determined by round state. [1](#0-0) 

When behavior is `UpdateValue`, critical validators are added: [2](#0-1) 

When behavior is `TinyBlock`, only 3 basic validators run (no additional providers added by the switch statement). This means `UpdateValueValidationProvider` and `LibInformationValidationProvider` are skipped.

**Root Cause**: The system determines expected behavior via `GetConsensusBehaviour()`: [3](#0-2) 

When `OutValue == null`, the miner should execute `UpdateValue` behavior. However, no validator checks that the claimed behavior in `extraData.Behaviour` matches this expectation.

**Exploitation Path**:
1. Miner has `OutValue == null` (should do `UpdateValue`)
2. Miner generates consensus extra data claiming `TinyBlock` behavior instead
3. `ValidateBeforeExecution` uses the claimed behavior to select validators
4. Only basic validators run (MiningPermission, TimeSlot, ContinuousBlocks)
5. `UpdateValueValidationProvider` (checks OutValue filled) is bypassed: [4](#0-3) 

6. `LibInformationValidationProvider` (validates LIB heights) is bypassed: [5](#0-4) 

7. `ProcessTinyBlock` executes, incrementing counters but leaving `OutValue` null: [6](#0-5) 

8. Attacker can repeat this up to `MaximumTinyBlocksCount` (8) times: [7](#0-6) 

### Impact Explanation

**Consensus Integrity Compromise**:
- Miners never publish `OutValue`/`Signature`, breaking consensus randomness generation used for next round miner selection and cryptographic sortition
- LIB (Last Irreversible Block) height validation bypassed, allowing miners to provide arbitrary `ImpliedIrreversibleBlockHeight` values that get recorded in state: [8](#0-7) 

- If multiple colluding miners exploit this (even 2-3 out of typical 17 miners), they can:
  - Delay round progression by never publishing OutValue
  - Manipulate LIB calculations affecting finality guarantees
  - Compromise random number generation for block production ordering

**Severity**: Critical - directly undermines consensus security properties (liveness, safety, randomness) that the entire blockchain depends on.

### Likelihood Explanation

**Attacker Capabilities**: Any miner in the current miner list (realistic - miners exist by design).

**Attack Complexity**: Low
- Miner modifies their consensus command generation to claim `TinyBlock` instead of `UpdateValue`
- No smart contract exploitation or cryptographic breaking required
- Simply requires producing blocks with wrong behavior flag

**Feasibility**: High
- Entry point: Standard block production (miners produce blocks normally)
- No special permissions beyond being a miner
- Can be executed repeatedly within time slot limits (up to 8 blocks per round per miner)
- Detection: Difficult during attack window as validators accept the blocks as valid

**Economic Rationality**: 
- Cost: Only normal block production costs
- Benefit: Consensus manipulation could enable various attacks (DoS, chain stalls, finality manipulation)
- A rational attacker seeking to disrupt the chain would find this cost-effective

### Recommendation

**Add Behavior Verification Provider**:

Create `BehaviorTypeValidationProvider` that validates the claimed behavior matches expected behavior based on round state:

```csharp
public class BehaviorTypeValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var baseRound = validationContext.BaseRound;
        var pubkey = validationContext.SenderPubkey;
        var claimedBehavior = validationContext.ExtraData.Behaviour;
        
        // Determine expected behavior
        var expectedBehavior = DetermineExpectedBehavior(baseRound, pubkey, validationContext);
        
        if (claimedBehavior != expectedBehavior)
        {
            return new ValidationResult 
            { 
                Message = $"Behavior mismatch: claimed {claimedBehavior}, expected {expectedBehavior}" 
            };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

**Register as Basic Provider**:

Add to the basic providers list in `ValidateBeforeExecution`: [9](#0-8) 

**Invariant Check**: `claimedBehavior == GetConsensusBehaviour(currentState, miner)` must hold for all blocks.

**Test Cases**:
1. Miner with `OutValue == null` claiming `TinyBlock` → validation fails
2. Miner with `OutValue != null` in time slot claiming `UpdateValue` → validation fails  
3. Round termination conditions claiming wrong behavior → validation fails

### Proof of Concept

**Initial State**:
- Miner "Alice" in miner list for current round
- Alice's `OutValue == null` (hasn't produced block this round)
- Current round number: 100, block height: 10000

**Attack Sequence**:

1. Alice calls `GetConsensusCommand()` → returns `UpdateValue` (expected behavior)

2. Alice crafts malicious consensus extra data:
   - Sets `behaviour = AElfConsensusBehaviour.TinyBlock` (instead of `UpdateValue`)
   - Creates `TinyBlockInput` instead of `UpdateValueInput`
   - Omits `OutValue` and `Signature` fields

3. Alice produces block with this extra data

4. Validation executes:
   - `ValidateBeforeExecution` reads `extraData.Behaviour = TinyBlock`
   - Only 3 basic providers registered (no `UpdateValueValidationProvider`, no `LibInformationValidationProvider`)
   - Basic validators pass (Alice is in miner list, time slot valid)

5. Execution:
   - `ProcessTinyBlock` called instead of `ProcessUpdateValue`
   - `ActualMiningTimes` incremented, `ProducedBlocks` incremented
   - `OutValue` remains `null` in state

6. Alice repeats steps 2-5 up to 8 times (MaximumTinyBlocksCount)

**Expected Result**: Block validation fails with "Behavior mismatch: claimed TinyBlock, expected UpdateValue"

**Actual Result**: All blocks validate successfully, Alice produces 8 blocks without ever publishing OutValue/Signature, bypassing critical consensus validations

**Success Condition**: After 8 blocks, Alice's `OutValue` still `null` in `State.Rounds[100].RealTimeMinersInformation["Alice"]`, demonstrating complete bypass of UpdateValue requirements.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-92)
```csharp
        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L12-19)
```csharp
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-30)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
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
