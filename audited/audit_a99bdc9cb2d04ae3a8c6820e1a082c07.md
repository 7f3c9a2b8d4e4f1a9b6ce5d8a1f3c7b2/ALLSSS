### Title
Consensus Failure via Malformed Signature in NextRound Transition

### Summary
A malicious but authorized miner can submit a `NextRoundInput` containing `MinerInRound` objects with malformed `Signature` fields (empty `ByteString` value). This bypasses all validation providers and gets stored in state. When the next round transition attempts to generate round information, the `CalculateNextExtraBlockProducerOrder()` function calls `signature.ToInt64()` on the malformed signature, causing `BitConverter.ToInt64()` to throw an `ArgumentException` and halting consensus progression.

### Finding Description

**Exact Location:** [1](#0-0) 

**Root Cause:**
The function checks if `Signature != null` but fails to validate that the `Signature.Value` ByteString has sufficient length for `ToInt64()` conversion: [2](#0-1) 

The `Hash.ToInt64()` method chains to `ByteExtensions.ToInt64()` which directly calls `BitConverter.ToInt64()` without length validation: [3](#0-2) [4](#0-3) 

`BitConverter.ToInt64()` requires at least 8 bytes and throws `ArgumentException` if the array is shorter.

**Why Protections Fail:**

The `UpdateValueValidationProvider` does validate `Signature.Value.Any()`: [5](#0-4) 

However, this validator is **only applied to `UpdateValue` behavior**, not `NextRound`: [6](#0-5) 

For `NextRound` behavior, the validation uses:
- `NextRoundMiningOrderValidationProvider` - validates mining order count, not signatures
- `RoundTerminateValidationProvider` - validates round/term number and InValue nullity, not signatures [7](#0-6) 

**Execution Path:**

1. Authorized miner calls `NextRound()`: [8](#0-7) 

2. After `PreCheck()` authorization, `ProcessNextRound()` converts the input and stores it: [9](#0-8) 

3. The malformed `Round` is added to state via `AddRoundInformation()`: [10](#0-9) 

4. When generating the next round, the poisoned round is retrieved from state: [11](#0-10) 

5. `GenerateNextRoundInformation()` calls `CalculateNextExtraBlockProducerOrder()` on the current (poisoned) round: [12](#0-11) 

6. Exception thrown when `BitConverter.ToInt64()` receives an array with fewer than 8 bytes.

### Impact Explanation

**Concrete Harm:**
- **Consensus Halted:** All attempts to generate the next round fail with an unhandled exception
- **Blockchain DoS:** No blocks can be produced beyond the poisoned round, completely stopping chain progression
- **Non-deterministic Failure:** The system expects deterministic extra block producer selection but instead encounters an exception

**Who is Affected:**
- All block producers attempting to mine after the poisoned round
- All users of the blockchain (no transactions can be processed)
- The entire AEDPoS consensus mechanism

**Severity Justification:**
This is a **HIGH severity** consensus integrity violation. A single malicious miner can permanently halt blockchain progression with a simple malformed input that bypasses all validation.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires authorized miner status (must pass `PreCheck()` which validates membership in current/previous round's miner list) [13](#0-12) 

- Does NOT require trusted role beyond being an elected miner

**Attack Complexity:**
- **Low:** Simply create a `NextRoundInput` protobuf message with `Signature = new Hash()` (empty ByteString)
- No complex cryptography or timing requirements
- Single transaction execution

**Feasibility Conditions:**
- Attacker must be an authorized miner in current or previous round
- Standard protobuf message construction capability
- No special economic resources required beyond miner status

**Detection:**
- Would manifest immediately when any miner attempts to generate the subsequent round
- Observable as consensus failure in network logs
- However, by that time damage is done (round already in state)

**Probability:**
Medium-High for a malicious or compromised miner. The attack is trivial to execute and has maximum impact with minimal effort.

### Recommendation

**Code-Level Mitigation:**

Add signature length validation in `CalculateNextExtraBlockProducerOrder()`:

```csharp
var signature = firstPlaceInfo.Signature;
// Validate signature has sufficient bytes for ToInt64()
if (signature == null || signature.Value == null || signature.Value.Length < 8)
    return 1; // Default to first miner position if signature invalid
var sigNum = signature.ToInt64();
```

**Alternatively**, add signature validation to `RoundTerminateValidationProvider`:

```csharp
// In ValidationForNextRound, after line 32:
if (extraData.Round.RealTimeMinersInformation.Values.Any(m => 
    m.Signature != null && (m.Signature.Value == null || m.Signature.Value.Length < 32)))
    return new ValidationResult { Message = "Invalid signature format in next round." };
```

**Invariant Checks:**
- All `MinerInRound.Signature` fields must either be null OR have `Value.Length == 32` (standard hash size)
- Add assertion in `AddRoundInformation()` to validate all signatures before state modification

**Test Cases:**
- Test `CalculateNextExtraBlockProducerOrder()` with signature having empty ByteString
- Test `CalculateNextExtraBlockProducerOrder()` with signature having 1-7 byte ByteString
- Test `NextRound()` rejection of inputs with malformed signatures
- Test consensus recovery after attempted malformed signature injection

### Proof of Concept

**Initial State:**
- Blockchain at round N with 7 valid miners
- Current round has proper signatures from previous round transitions

**Attack Steps:**

1. Malicious miner (authorized, in current round's miner list) crafts a `NextRoundInput` for round N+1:
   ```
   NextRoundInput {
     RoundNumber: N+1,
     RealTimeMinersInformation: {
       "MinerPubkey1": MinerInRound {
         Order: 1,
         Signature: new Hash() { Value: ByteString.Empty },  // MALFORMED
         ... other valid fields ...
       },
       ... other miners ...
     }
   }
   ```

2. Call `NextRound(maliciousInput)`:
   - Passes `PreCheck()` (caller is authorized miner)
   - Passes `NextRoundMiningOrderValidationProvider` (only checks count)
   - Passes `RoundTerminateValidationProvider` (only checks round number and InValues)
   - `ProcessNextRound()` stores poisoned round N+1 in state

3. Any miner attempts to produce a block for round N+2:
   - Calls `GetConsensusBlockExtraData()`
   - Retrieves poisoned round N+1 from state
   - Calls `GenerateNextRoundInformation(poisonedRound, ...)`
   - Calls `CalculateNextExtraBlockProducerOrder()` on poisoned round
   - Line 118: `firstPlaceInfo.Signature != null` passes (Signature object exists)
   - Line 119: `signature.ToInt64()` → `Hash.ToInt64()` → `ByteExtensions.ToInt64()` → `BitConverter.ToInt64(emptyArray, 0)`

**Expected Result:**
Deterministic calculation of extra block producer order for round N+2

**Actual Result:**
`ArgumentException` thrown by `BitConverter.ToInt64()` when attempting to read 8 bytes from 0-byte array. Consensus halted, no blocks can be produced for round N+2 or any subsequent round.

**Success Condition:**
Blockchain stuck at round N+1, unable to progress. All miners encounter the same exception when attempting to generate consensus data for round N+2.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** src/AElf.Types/Types/Hash.cs (L105-108)
```csharp
        public long ToInt64()
        {
            return ToByteArray().ToInt64(true);
        }
```

**File:** src/AElf.Types/Extensions/ByteExtensions.cs (L53-57)
```csharp
        public static long ToInt64(this byte[] bytes, bool bigEndian)
        {
            var needReverse = !bigEndian ^ BitConverter.IsLittleEndian;
            return BitConverter.ToInt64(needReverse ? bytes.Reverse().ToArray() : bytes, 0);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L13-42)
```csharp
    private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);

        Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");

        TryToGetCurrentRoundInformation(out var currentRound);

        var publicKeyBytes = triggerInformation.Pubkey;
        var pubkey = publicKeyBytes.ToHex();

        var information = new AElfConsensusHeaderInformation();
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextRound:
                information = GetConsensusExtraDataForNextRound(currentRound, pubkey,
                    triggerInformation);
```
