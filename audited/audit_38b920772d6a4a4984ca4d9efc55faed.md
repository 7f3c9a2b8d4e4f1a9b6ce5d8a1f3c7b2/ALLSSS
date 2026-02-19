### Title
Missing Validation of Previous Round Linkage in Consensus Command Hint Enables Secret Sharing State Corruption During Chain Reorganizations

### Summary
The `NormalBlockCommandStrategy` includes a `_previousRoundId` in the consensus command hint that is never validated against the actual previous round's `RoundId` in blockchain state. During chain reorganizations or round transitions, off-chain components use this unvalidated hint to fetch secret sharing pieces from cache, which are then stored on-chain without verification. This corrupts the secret sharing state and compromises random number generation integrity.

### Finding Description

The vulnerability exists in the consensus command generation and validation flow:

**Root Cause - Missing Validation:**

The `NormalBlockCommandStrategy` constructor accepts a `previousRoundId` parameter and embeds it directly into the consensus hint without any validation: [1](#0-0) [2](#0-1) 

The `previousRoundId` is obtained from state when `GetConsensusCommand` is called: [3](#0-2) 

**Off-Chain Hint Usage Without Validation:**

The off-chain `AEDPoSTriggerInformationProvider` uses the hint's `PreviousRoundId` to fetch previous in values and the hint's `RoundId` to fetch secret sharing pieces from cache: [4](#0-3) 

**On-Chain Validation Gaps:**

During block validation, the system retrieves the previous round directly from state based on the current round number, not from the hint: [5](#0-4) 

The `UpdateValueValidationProvider` only validates the previous in value if it's published, which is optional: [6](#0-5) 

Critically, miners are explicitly allowed to skip publishing their previous in values: [7](#0-6) 

**Unvalidated Secret Sharing Storage:**

Secret sharing pieces fetched using the potentially incorrect hint are stored without any validation: [8](#0-7) [9](#0-8) 

### Impact Explanation

**Consensus Integrity Compromise:**

1. **Secret Sharing Corruption**: Wrong secret sharing pieces from mismatched rounds are stored in the blockchain state, corrupting the Shamir's Secret Sharing scheme used for random number generation.

2. **Random Number Generation Failure**: The `RevealSharedInValues` function uses stored encrypted/decrypted pieces to reconstruct in values for random number generation: [10](#0-9) 

With corrupted pieces, this reconstruction will produce incorrect or fail entirely, breaking the randomness beacon.

3. **Chain State Inconsistency**: Different nodes experiencing chain reorganizations at different times may store different secret sharing pieces for the same round, leading to divergent views of consensus state and potential consensus halts.

4. **Miner Selection Impact**: Corrupted random numbers affect future miner ordering and consensus decisions, potentially enabling censorship or manipulation of block production.

**Severity Justification:**
This is a **Critical** vulnerability because it directly compromises consensus integrity - a fundamental invariant of the blockchain. The impact extends beyond individual transactions to the entire consensus mechanism's reliability and security.

### Likelihood Explanation

**Attack Feasibility:**

1. **Natural Occurrence During Reorganizations**: This vulnerability triggers naturally during chain reorganizations without requiring malicious intent. When a node switches from one chain fork to another:
   - The consensus command was generated based on Fork A's state
   - The node attempts to produce a block on Fork B after reorganization
   - The hint's `PreviousRoundId` refers to Fork A's previous round
   - Fork B's actual previous round has a different `RoundId`

2. **Round Transition Race Condition**: During normal operation, if one miner triggers `NextRound` while another miner is producing an `UpdateValue` block:
   - The second miner's command was generated for Round N
   - Round advances to N+1 before their block is produced
   - The hint's `PreviousRoundId` points to Round N-1
   - The actual previous round is now Round N

3. **No Attacker Capability Required**: The vulnerability exploits the legitimate consensus protocol flow. No special permissions, stake manipulation, or protocol violations are needed.

4. **Detection Difficulty**: Since miners can legitimately skip publishing previous in values, blocks with corrupted secret sharing pieces appear valid and pass all current validation checks.

**Probability Assessment:**
- Chain reorganizations occur regularly in distributed systems
- Multiple miners operate concurrently, creating race conditions
- No cryptographic or economic barriers prevent exploitation
- **Overall Likelihood: HIGH**

### Recommendation

**Immediate Fix - Add PreviousRoundId Validation:**

Add explicit validation in the `UpdateValueValidationProvider` to verify the hint's `PreviousRoundId` matches the actual previous round:

```csharp
public class UpdateValueValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Existing validations...
        
        // NEW: Validate PreviousRoundId from hint matches state
        if (!ValidatePreviousRoundId(validationContext))
            return new ValidationResult { Message = "Previous round ID mismatch with blockchain state." };
        
        // ... rest of validations
    }
    
    private bool ValidatePreviousRoundId(ConsensusValidationContext validationContext)
    {
        // Extract hint from consensus command (passed through context)
        var hint = validationContext.ConsensusHint; // Need to add this to context
        if (hint == null || hint.PreviousRoundId == 0) 
            return true; // First round or no hint
            
        if (validationContext.PreviousRound == null || validationContext.PreviousRound.IsEmpty)
            return hint.PreviousRoundId == 0;
            
        return hint.PreviousRoundId == validationContext.PreviousRound.RoundId;
    }
}
```

**Required Context Changes:**

Modify `ConsensusValidationContext` to include the hint: [11](#0-10) 

Add a field for the consensus hint and populate it during validation setup.

**Test Cases:**

1. Test chain reorganization scenario with different `RoundId` values
2. Test round transition with stale consensus command
3. Test validation rejection when `PreviousRoundId` mismatch detected
4. Test secret sharing integrity after rejected blocks with wrong hints

### Proof of Concept

**Initial State:**
- Blockchain has reached Round 10 (RoundId = 100) on Chain A
- Previous round is Round 9 (RoundId = 90)
- Secret sharing is enabled
- Multiple miners are active

**Exploitation Steps:**

1. **Command Generation on Chain A:**
   - Miner calls `GetConsensusCommand` at time T1
   - Command generated with: `RoundId=100`, `PreviousRoundId=90`
   - Miner prepares to produce block

2. **Chain Reorganization Occurs:**
   - At time T2, Chain B becomes the main chain (longer/heavier)
   - Chain B's Round 10 has `RoundId=105` (different miners/timing)
   - Chain B's Round 9 has `RoundId=95`

3. **Block Production on Chain B:**
   - Miner produces block using command from Chain A
   - `AEDPoSTriggerInformationProvider` uses hint's `PreviousRoundId=90`
   - Attempts to fetch previous in value from cache using RoundId=90
   - Fetches encrypted/decrypted pieces using `RoundId=100` (from Chain A)

4. **Validation Passes Incorrectly:**
   - `ValidateBeforeExecution` retrieves Chain B's Round 9 (RoundId=95) as previous round
   - Miner chooses not to publish `PreviousInValue` (permissible)
   - `UpdateValueValidationProvider.ValidatePreviousInValue` returns `true` (line 42-46)
   - No validation checks hint's `PreviousRoundId=90` against actual `PreviousRound.RoundId=95`
   - Block validation passes

5. **Corruption Stored:**
   - `PerformSecretSharing` stores the secret pieces from Chain A's rounds
   - These pieces don't match Chain B's round structure
   - Round state now contains inconsistent secret sharing data

**Expected vs Actual Result:**

**Expected:** Block should be rejected due to `PreviousRoundId` mismatch with actual previous round

**Actual:** Block is accepted and corrupted secret sharing pieces are stored in blockchain state

**Success Condition:** Verify that Chain B's Round 10 contains secret sharing pieces that don't correspond to Chain B's Round 9, causing subsequent `RevealSharedInValues` operations to fail or produce incorrect random values.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L14-21)
```csharp
        private readonly long _previousRoundId;

        public NormalBlockCommandStrategy(Round currentRound, string pubkey, Timestamp currentBlockTime,
            long previousRoundId) : base(
            currentRound, pubkey, currentBlockTime)
        {
            _previousRoundId = previousRoundId;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L28-40)
```csharp
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint
                {
                    Behaviour = AElfConsensusBehaviour.UpdateValue,
                    RoundId = CurrentRound.RoundId,
                    PreviousRoundId = _previousRoundId
                }.ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                // Cancel mining after time slot of current miner because of the task queue.
                MiningDueTime = CurrentRound.GetExpectedMiningTime(Pubkey).AddMilliseconds(MiningInterval),
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L34-37)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                TryToGetPreviousRoundInformation(out var previousRound);
                return new ConsensusCommandProvider(new NormalBlockCommandStrategy(currentRound, pubkey,
                    currentBlockTime, previousRound.RoundId)).GetConsensusCommand();
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L92-116)
```csharp
        if (hint.Behaviour == AElfConsensusBehaviour.UpdateValue)
        {
            var inValue = _inValueCache.GetInValue(hint.RoundId);
            var trigger = new AElfConsensusTriggerInformation
            {
                Pubkey = Pubkey,
                InValue = inValue,
                PreviousInValue = _inValueCache.GetInValue(hint.PreviousRoundId),
                Behaviour = hint.Behaviour,
                RandomNumber = ByteString.CopyFrom(randomProof)
            };

            var secretPieces = _secretSharingService.GetEncryptedPieces(hint.RoundId);
            foreach (var secretPiece in secretPieces)
                trigger.EncryptedPieces.Add(secretPiece.Key, ByteString.CopyFrom(secretPiece.Value));

            var decryptedPieces = _secretSharingService.GetDecryptedPieces(hint.RoundId);
            foreach (var decryptedPiece in decryptedPieces)
                trigger.DecryptedPieces.Add(decryptedPiece.Key, ByteString.CopyFrom(decryptedPiece.Value));

            var revealedInValues = _secretSharingService.GetRevealedInValues(hint.RoundId);
            foreach (var revealedInValue in revealedInValues)
                trigger.RevealedInValues.Add(revealedInValue.Key, revealedInValue.Value);

            return trigger.ToBytesValue();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-297)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L13-53)
```csharp
    private void RevealSharedInValues(Round currentRound, string publicKey)
    {
        Context.LogDebug(() => "About to reveal shared in values.");

        if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L8-41)
```csharp
public class ConsensusValidationContext
{
    public long CurrentTermNumber { get; set; }
    public long CurrentRoundNumber { get; set; }

    /// <summary>
    ///     We can trust this because we already validated the pubkey
    ///     during `AEDPoSExtraDataExtractor.ExtractConsensusExtraData`
    /// </summary>
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();

    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;

    /// <summary>
    ///     Previous round information fetch from StateDb.
    /// </summary>
    public Round PreviousRound { get; set; }

    /// <summary>
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
    public LatestPubkeyToTinyBlocksCount LatestPubkeyToTinyBlocksCount { get; set; }

    public AElfConsensusHeaderInformation ExtraData { get; set; }
}
```
