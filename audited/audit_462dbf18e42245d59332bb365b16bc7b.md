### Title
Missing LIB Upper Bound Validation in NextRound/NextTerm Enables Consensus DOS via Integer Overflow

### Summary
The `LibInformationValidationProvider` only validates LIB values for `UpdateValue` behavior, but not for `NextRound` or `NextTerm` behaviors. A malicious miner can inject `ConfirmedIrreversibleBlockHeight = long.MaxValue` in NextRound/NextTerm consensus data, which passes validation but causes arithmetic overflow in `GetMaximumBlocksCount()`, permanently halting consensus.

### Finding Description

**Root Cause**: The validation architecture has a critical gap:

1. `LibInformationValidationProvider` checks LIB values only for `UpdateValue` behavior [1](#0-0) , but `NextRound` and `NextTerm` behaviors use only `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`, neither of which validate LIB bounds.

2. The `ConfirmedIrreversibleBlockHeight` field is excluded from the hash comparison in `ValidateConsensusAfterExecution` [2](#0-1) , meaning a miner can modify this value without detection by the post-execution hash check.

3. When `NextRound` or `NextTerm` executes, the malicious Round object (with `ConfirmedIrreversibleBlockHeight = long.MaxValue`) is stored directly to state [3](#0-2) .

4. On the next block, `GetMaximumBlocksCount()` reads this value and attempts `currentHeight.Sub(libBlockHeight)` [4](#0-3) , where `Sub()` uses checked arithmetic [5](#0-4) .

5. Computing `currentHeight - long.MaxValue` (e.g., `1000 - 9223372036854775807`) causes `OverflowException`, crashing every subsequent block execution.

**Why Existing Protections Fail**:
- `LibInformationValidationProvider` validates LIB backward movement [6](#0-5)  but only applies to `UpdateValue`, not `NextRound`/`NextTerm`
- `RoundTerminateValidationProvider` only checks round/term numbers and InValue nullity [7](#0-6) , ignoring LIB values entirely
- Hash-based validation in `ValidateConsensusAfterExecution` omits LIB fields from comparison [8](#0-7) 

### Impact Explanation

**Operational DOS**: Complete consensus halt. Once the malicious LIB value enters state, all subsequent blocks fail during `ProcessConsensusInformation` → `GetMaximumBlocksCount()` → arithmetic overflow [9](#0-8) .

**Scope**: Affects entire blockchain - no blocks can be produced after the attack. Recovery requires hard fork or chain rollback to before the malicious round was committed.

**Severity Justification**: High/Critical - permanent DOS with no automatic recovery mechanism. Only active miners can trigger, but single malicious miner suffices.

### Likelihood Explanation

**Attacker Capabilities**: Must be an active miner in the current miner list, which requires either:
- Being elected through the election contract (high barrier)
- For sidechains, being in the configured miner set

**Attack Complexity**: Low once miner status achieved:
1. Wait for assigned NextRound or NextTerm time slot
2. Call `GetConsensusCommand` to get legitimate consensus data [10](#0-9) 
3. Modify `Round.ConfirmedIrreversibleBlockHeight` to `long.MaxValue` in the extra data before block production
4. Produce block - passes all validation
5. Next block by any miner crashes the chain

**Feasibility Conditions**: 
- Requires miner privileges (non-trivial but achievable)
- No runtime detection - malicious value appears valid until arithmetic overflow
- Single execution succeeds; all subsequent blocks fail

**Probability**: Medium-High given miner access. Miners have economic incentive to maintain chain health, but a compromised miner, exiting miner, or Byzantine actor can execute this attack with high success rate.

### Recommendation

**Immediate Fix**: Add `LibInformationValidationProvider` to NextRound and NextTerm validation:

```
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
``` [11](#0-10) 

**Enhanced Fix**: Add upper bound check in `LibInformationValidationProvider.ValidateHeaderInformation()`:

```
if (providedRound.ConfirmedIrreversibleBlockHeight > Context.CurrentHeight + ReasonableHeightBuffer)
{
    validationResult.Message = "LIB height unreasonably high.";
    return validationResult;
}
```

Where `ReasonableHeightBuffer` could be `1000` blocks (allowing for some propagation delay but preventing extreme values).

**Test Cases**:
1. Verify NextRound with `ConfirmedIrreversibleBlockHeight = long.MaxValue` is rejected
2. Verify NextTerm with `ConfirmedIrreversibleBlockHeight = currentHeight + 10000` is rejected  
3. Verify legitimate LIB increments pass validation
4. Integration test: confirm `GetMaximumBlocksCount()` never encounters overflow after patch

### Proof of Concept

**Initial State**:
- Chain at height 1000, current round 50
- Current round has `ConfirmedIrreversibleBlockHeight = 980`
- Attacker is elected miner "MinerA"

**Attack Steps**:
1. MinerA's turn to produce NextRound block (round 51)
2. MinerA calls `GetConsensusCommand` → receives `AElfConsensusBehaviour.NextRound`
3. MinerA calls `GetConsensusExtraData` → receives legitimate Round with `ConfirmedIrreversibleBlockHeight = 980`
4. MinerA modifies: `round.ConfirmedIrreversibleBlockHeight = 9223372036854775807` (long.MaxValue)
5. MinerA produces block with modified consensus data
6. Block validation runs:
   - `ValidateConsensusBeforeExecution`: No LibInformationValidationProvider for NextRound → passes [12](#0-11) 
   - `ValidateConsensusAfterExecution`: LIB not in hash → passes [13](#0-12) 
7. Block executes: `ProcessNextRound` stores malicious round at state[51] [14](#0-13) 
8. Next block (height 1001, any miner):
   - `ProcessConsensusInformation` calls `GetMaximumBlocksCount()` [9](#0-8) 
   - Reads `libBlockHeight = 9223372036854775807` from state[51] [15](#0-14) 
   - Attempts: `1001.Sub(9223372036854775807)` [16](#0-15) 
   - `Sub()` uses `checked` arithmetic → `OverflowException` thrown [5](#0-4) 
   - Block execution fails

**Expected Result**: Block 1001 and all subsequent blocks fail with `OverflowException`, consensus permanently halted.

**Success Condition**: Chain cannot produce blocks beyond height 1000 without rollback/fork.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L68-68)
```csharp
        var minersCountInTheory = GetMaximumBlocksCount();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-67)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");

        // If R_LIB + 2 < R < R_LIB + CB1, CB goes to Min(T(L2 * (CB1 - (R - R_LIB)) / A), CB0), while CT stays same as before.
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }

        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-47)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }

    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L20-57)
```csharp
    private ConsensusCommand GetConsensusCommand(AElfConsensusBehaviour behaviour, Round currentRound,
        string pubkey, Timestamp currentBlockTime = null)
    {
        if (SolitaryMinerDetection(currentRound, pubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        Context.LogDebug(() => $"Params to get command: {behaviour}, {pubkey}, {currentBlockTime}");

        if (currentRound.RoundNumber == 1 && behaviour == AElfConsensusBehaviour.UpdateValue)
            return new ConsensusCommandProvider(new FirstRoundCommandStrategy(currentRound, pubkey,
                currentBlockTime, behaviour)).GetConsensusCommand();

        switch (behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                TryToGetPreviousRoundInformation(out var previousRound);
                return new ConsensusCommandProvider(new NormalBlockCommandStrategy(currentRound, pubkey,
                    currentBlockTime, previousRound.RoundId)).GetConsensusCommand();

            case AElfConsensusBehaviour.NextRound:
            case AElfConsensusBehaviour.NextTerm:
                return new ConsensusCommandProvider(
                        new TerminateRoundCommandStrategy(currentRound, pubkey, currentBlockTime,
                            behaviour == AElfConsensusBehaviour.NextTerm))
                    .GetConsensusCommand();

            case AElfConsensusBehaviour.TinyBlock:
            {
                var consensusCommand =
                    new ConsensusCommandProvider(new TinyBlockCommandStrategy(currentRound, pubkey,
                        currentBlockTime, GetMaximumBlocksCount())).GetConsensusCommand();
                return consensusCommand;
            }

            default:
                return ConsensusCommandProvider.InvalidConsensusCommand;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
    }
```
