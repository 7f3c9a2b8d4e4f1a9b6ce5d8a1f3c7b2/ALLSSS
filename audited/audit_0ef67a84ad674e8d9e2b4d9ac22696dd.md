### Title
NextRoundMiningOrderValidationProvider Validates Wrong Round Object Enabling Mining Order Manipulation

### Summary
The NextRoundMiningOrderValidationProvider.ValidateHeaderInformation() function checks `ProvidedRound` (the newly generated next round) instead of `BaseRound` (the current round being transitioned from). Since the next round is freshly generated with empty FinalOrderOfNextRound and OutValue fields, the validation always passes (0 == 0), rendering it completely ineffective. This allows malicious miners to manipulate FinalOrderOfNextRound values during UpdateValue transactions without detection, enabling them to control mining order in subsequent rounds.

### Finding Description

**Root Cause Location:** [1](#0-0) 

The validation incorrectly checks `validationContext.ProvidedRound` at line 14. During NextRound behavior, ProvidedRound contains the newly generated next round object returned from `GenerateNextRoundInformation`: [2](#0-1) 

The GenerateNextRoundInformation method creates fresh MinerInRound objects that do not carry over FinalOrderOfNextRound or OutValue from the current round: [3](#0-2) 

**Why Validation Fails:**

The validation should verify that in the CURRENT round (BaseRound), all miners who mined blocks (`OutValue != null`) have properly determined their next round order (`FinalOrderOfNextRound > 0`). Instead, it checks the NEXT round (ProvidedRound), where:
- All MinerInRound objects are newly created
- FinalOrderOfNextRound is never set (remains 0)
- OutValue is never set (remains null)
- Therefore: `distinctCount = 0` and `miners with OutValue != null = 0`, so `0 == 0` always passes

**Attack Vector:**

During UpdateValue behavior, FinalOrderOfNextRound can be manipulated via TuneOrderInformation: [4](#0-3) 

ProcessUpdateValue applies TuneOrderInformation from the transaction input without any validation. TuneOrderInformation is extracted from the consensus extra data: [5](#0-4) 

A malicious miner can modify the Round object in their consensus extra data before broadcasting their block, changing FinalOrderOfNextRound values. No validation exists to verify these values during UpdateValue: [6](#0-5) 

Only UpdateValueValidationProvider and LibInformationValidationProvider run for UpdateValue behavior - neither validates FinalOrderOfNextRound.

### Impact Explanation

**Consensus Integrity Violation:**
- Attackers can arbitrarily manipulate the mining order for subsequent rounds
- Breaks the cryptographic randomness intended by signature-based order calculation in ApplyNormalConsensusData
- Violates the critical invariant: "Correct round transitions and miner schedule integrity"

**Specific Harms:**
1. **Favorable Position Manipulation**: Attacker sets their FinalOrderOfNextRound to 1, ensuring they mine first in the next round for consistent MEV extraction or reduced risk of missing time slots
2. **Competitor Disadvantage**: Attacker assigns unfavorable orders to competing miners or creates order conflicts that disrupt their mining
3. **Consensus Predictability**: Repeated manipulation across rounds allows attacker to control long-term mining patterns, undermining consensus fairness
4. **Economic Damage**: Legitimate miners lose fair access to block rewards and transaction fees

**Affected Parties:**
- All honest miners suffer reduced and unfair mining opportunities
- Network users experience reduced decentralization and security
- Entire consensus mechanism's integrity is compromised

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be in the current miner list (achievable through normal consensus participation)
- Must be able to produce a block during UpdateValue behavior (happens regularly during their time slot)
- Requires no special privileges beyond being a scheduled miner

**Attack Complexity:**
- **Low complexity**: Simply modify the Round object in consensus extra data before broadcasting block
- Modification point is clear: after GetConsensusExtraDataToPublishOutValue returns but before block broadcast
- No complex cryptographic operations or race conditions required

**Feasibility Conditions:**
- Triggered during normal UpdateValue block production (happens every round for each miner)
- No special timing or state requirements
- Works regardless of other miners' behavior
- Repeatable across multiple rounds for sustained impact

**Detection Limitations:**
- No validation checks FinalOrderOfNextRound values during UpdateValue
- NextRoundMiningOrderValidationProvider checks wrong round and always passes
- Manipulation only becomes apparent when analyzing next round's mining order, by which point state is already updated
- Off-chain monitoring could detect but cannot prevent on-chain

**Probability Assessment:**
- **HIGH**: Any malicious miner can exploit this during their normal block production
- Attack success rate: ~100% (validation always passes with wrong round)
- Economic rationality: Clear benefit (favorable mining positions) with no cost or detection risk

### Recommendation

**Immediate Fix:**

Modify NextRoundMiningOrderValidationProvider to validate BaseRound instead of ProvidedRound: [1](#0-0) 

Change line 14 from:
```
var providedRound = validationContext.ProvidedRound;
```
To:
```
var providedRound = validationContext.BaseRound;
```

**Additional Validation:**

Add TuneOrderInformation validation during UpdateValue behavior. In UpdateValueValidationProvider or a new validator, verify that:
1. TuneOrderInformation only contains miners with actual order conflicts
2. Reassigned orders follow legitimate conflict resolution rules
3. Each miner's SupposedOrderOfNextRound matches their signature hash calculation

**Invariant Checks:**

Add assertion in ProcessUpdateValue before applying TuneOrderInformation: [7](#0-6) 

Verify that tuned orders are within valid range (1 to minersCount) and don't create duplicate assignments.

**Test Cases:**

1. Test NextRound validation with manipulated FinalOrderOfNextRound in BaseRound (should fail)
2. Test UpdateValue with invalid TuneOrderInformation (should fail validation)
3. Test legitimate conflict resolution still works correctly
4. Regression test: ensure validation uses BaseRound not ProvidedRound

### Proof of Concept

**Initial State:**
- Network has N miners in current round (e.g., N=5)
- Malicious miner M is scheduled to produce block at position 3
- Current round has miners with partially filled FinalOrderOfNextRound values

**Exploitation Steps:**

1. **Malicious Block Production (UpdateValue):**
   - Miner M's turn arrives, node calls GetConsensusExtraData(UpdateValue)
   - GetConsensusExtraDataToPublishOutValue executes normally, returns Round with legitimate FinalOrderOfNextRound
   - **Attack**: Before broadcasting block, miner M modifies the Round in consensus extra data:
     - Sets their own FinalOrderOfNextRound to 1 (to mine first in next round)
     - Optionally modifies competitors' FinalOrderOfNextRound to disadvantageous positions
   - Miner M broadcasts block with modified consensus extra data

2. **Validation Phase:**
   - Other nodes receive block, call ValidateConsensusBeforeExecution
   - UpdateValueValidationProvider runs, checks OutValue/Signature (passes - unrelated to order)
   - **Critical**: No validator checks FinalOrderOfNextRound values
   - Validation passes ✓

3. **State Update:**
   - GenerateConsensusTransactions extracts UpdateValueInput from modified Round
   - UpdateValue transaction executes via ProcessUpdateValue
   - Line 247 sets FinalOrderOfNextRound from input's SupposedOrderOfNextRound
   - Lines 259-260 apply malicious TuneOrderInformation
   - **State now contains manipulated FinalOrderOfNextRound values** ✓

4. **Round Transition (NextRound):**
   - Extra block producer triggers round transition
   - GetConsensusExtraDataForNextRound calls GenerateNextRoundInformation
   - **GenerateNextRoundInformation uses manipulated FinalOrderOfNextRound from state** (line 26)
   - Creates next round with miner M at position 1
   - ValidateConsensusBeforeExecution runs NextRoundMiningOrderValidationProvider
   - **Validation checks ProvidedRound (next round with empty values), finds 0 == 0, passes** ✓

**Expected vs Actual Result:**

**Expected:** NextRoundMiningOrderValidationProvider should detect that current round's FinalOrderOfNextRound was manipulated and reject the round transition.

**Actual:** Validation checks the wrong round (next round instead of current round), always finds 0 == 0, passes validation, and allows the manipulated mining order to take effect.

**Success Condition:**
- Miner M successfully mines first in next round (position 1) despite randomness calculation suggesting different order
- No validation error occurred
- State contains attacker-controlled mining order
- Attack is repeatable in subsequent rounds

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-260)
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

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
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
