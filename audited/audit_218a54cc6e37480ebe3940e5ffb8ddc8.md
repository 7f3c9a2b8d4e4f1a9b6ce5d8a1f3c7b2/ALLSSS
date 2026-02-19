### Title
Inconsistent LIB Fields in NextTerm Allow Manipulation of Mining Restrictions

### Summary
An authorized miner can provide inconsistent `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` values during term transitions, bypassing validation checks. These inconsistent values are stored in consensus state and used to determine mining status, allowing the attacker to either avoid mining restrictions or trigger unwarranted consensus DoS.

### Finding Description

The vulnerability exists in the NextTerm consensus transaction flow where LIB (Last Irreversible Block) field consistency is not validated. [1](#0-0) 

The `NextTermInput.Create()` method copies `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` from the input Round without any consistency validation between these two fields. [2](#0-1) 

The `NextTerm` method is public and accepts arbitrary `NextTermInput` values from authorized miners.

**Critical Validation Gap:** [3](#0-2) 

For NextTerm behavior, only `RoundTerminateValidationProvider` is added, which validates term/round number correctness but NOT the LIB fields. [4](#0-3) 

The `LibInformationValidationProvider` (which validates LIB fields don't go backwards) is ONLY added for UpdateValue behavior, not for NextTerm. Furthermore, it only checks monotonicity, not consistency between the two fields.

**Hash Validation Bypass:** [5](#0-4) 

The `GetCheckableRound()` method used for hash calculation in `ValidateConsensusAfterExecution` does NOT include `ConfirmedIrreversibleBlockHeight` or `ConfirmedIrreversibleBlockRoundNumber` fields. It only includes RoundNumber, TermNumber, RealTimeMinersInformation, and BlockchainAge. This means inconsistent LIB values will not be detected by the after-execution hash comparison.

**Storage Without Validation:** [6](#0-5) 

The `ProcessNextTerm` method stores the round information via `AddRoundInformation` without any additional validation of LIB field consistency.

### Impact Explanation

The inconsistent LIB values are used in critical consensus logic: [7](#0-6) 

The `GetMaximumBlocksCount()` method uses both `ConfirmedIrreversibleBlockRoundNumber` (to determine mining status) and `ConfirmedIrreversibleBlockHeight` (to calculate distance for event firing).

**Attack Scenario 1 - Bypass Mining Restrictions:**
- Attacker sets `ConfirmedIrreversibleBlockRoundNumber` to a high value (close to current round)
- Sets `ConfirmedIrreversibleBlockHeight` to a low value
- Result: System remains in Normal/Abnormal status allowing full mining capacity
- Should be in Severe status with restricted mining (1 block per miner)
- **Impact**: Undermines consensus safety by allowing excessive block production when the chain should be throttled

**Attack Scenario 2 - Consensus DoS:**
- Attacker sets `ConfirmedIrreversibleBlockRoundNumber` to a very low value
- Sets `ConfirmedIrreversibleBlockHeight` to a high value  
- Result: System enters Severe status incorrectly, restricting all miners to 1 block each
- **Impact**: Severely degrades consensus performance and chain throughput unnecessarily

**Attack Scenario 3 - Event Manipulation:**
- Fires `IrreversibleBlockHeightUnacceptable` events with incorrect distance values
- Could mislead monitoring systems or trigger incorrect downstream logic

The impact affects the entire consensus system's integrity, mining fairness, and operational stability.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an authorized miner in the current or next term's miner list
- Must be selected to perform the NextTerm transition (happens at term boundaries)

**Attack Complexity:** Low
- Simply craft a custom `NextTermInput` transaction with inconsistent values
- No complex state manipulation or timing requirements needed
- Transaction will pass all validation checks

**Feasibility Conditions:**
- The attacker must be an authorized miner when term transition occurs
- Terms typically transition every few days/weeks in AEDPoS
- Multiple miners could be in position to exploit this

**Detection Constraints:**
- The inconsistent values are stored in state and appear valid individually
- Only detectable by comparing the relationship between the two fields
- No automatic detection mechanism exists

**Probability:** Medium-High for an authorized malicious miner
- Authorized miners have regular opportunities at term boundaries
- Low technical barrier to exploit
- High impact makes it an attractive attack vector

### Recommendation

**1. Add LIB Consistency Validation for NextTerm:**

Modify the validation logic to include `LibInformationValidationProvider` for NextTerm behavior, similar to UpdateValue: [3](#0-2) 

Change to:
```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new LibInformationValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

**2. Enhance LibInformationValidationProvider:**

Add a consistency check between `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber`: [8](#0-7) 

Add validation that the round number and height are consistent (e.g., verify that the height corresponds to a reasonable block count given the round number).

**3. Include LIB Fields in Hash Calculation:**

Modify `GetCheckableRound()` to include LIB fields in the consensus hash: [5](#0-4) 

Add `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` to the checkable round structure.

**4. Add Regression Tests:**
- Test NextTerm with inconsistent LIB values (should fail)
- Test NextTerm with consistent LIB values (should succeed)
- Test that hash validation detects LIB field tampering

### Proof of Concept

**Initial State:**
- Current round number: 1000
- Current term number: 10
- Current `ConfirmedIrreversibleBlockHeight`: 50000
- Current `ConfirmedIrreversibleBlockRoundNumber`: 998
- Attacker is an authorized miner for the next term

**Attack Steps:**

1. **Obtain legitimate NextTerm consensus data:**
   - Call `GetConsensusCommand` to determine NextTerm is the correct behavior
   - Call `GetConsensusExtraData` to get the properly generated round information

2. **Craft malicious NextTermInput:**
   - Copy all fields from the legitimate consensus data
   - Modify `ConfirmedIrreversibleBlockHeight` to 10000 (much lower)
   - Keep `ConfirmedIrreversibleBlockRoundNumber` at 998 (correct value)
   - OR: Set `ConfirmedIrreversibleBlockRoundNumber` to 900 (much lower)
   - Keep `ConfirmedIrreversibleBlockHeight` at 50000 (correct value)

3. **Submit malicious transaction:**
   - Call `NextTerm(maliciousNextTermInput)`
   - Transaction passes `ValidateBeforeExecution` (no LIB consistency check)
   - Transaction passes `ValidateAfterExecution` (hash excludes LIB fields)
   - Inconsistent values stored in `State.Rounds[newRoundNumber]`

4. **Verify exploitation:**
   - Call `GetMaximumBlocksCount()` 
   - Observe incorrect mining status determination
   - Either: Severe status avoided when it should be active (allowing excessive mining)
   - Or: Severe status triggered incorrectly (causing consensus DoS)

**Expected vs Actual:**
- **Expected**: Validation should reject NextTermInput with inconsistent LIB fields
- **Actual**: Transaction succeeds and stores inconsistent values, breaking consensus integrity

**Success Condition:** 
Query `GetCurrentRoundInformation()` and observe that `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` are inconsistent with each other, causing incorrect mining behavior in subsequent blocks.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
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

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-66)
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
```
