### Title
Failed Miner Can Exploit Weak Permission Check to Gain Undeserved Block Production Credit via NextTerm

### Summary
The `PreCheck()` function in the consensus contract uses an OR condition that allows miners present in the previous round to execute NextTerm transactions, even if they are not in the current round. This enables a failed miner who was removed from the current round to craft and submit NextTerm transactions, bypassing the stricter block-level validation that only checks the block producer's permissions. The attacker gains undeserved credit for block production in the election contract, affecting their election standing and reward distribution.

### Finding Description

The vulnerability exists in the permission validation logic for consensus operations. There are two layers of validation with different checking scopes:

**Block-Level Validation (Stricter):** [1](#0-0) 

This validation checks if the BLOCK PRODUCER (identified via consensus extra data SenderPubkey matching the block's SignerPubkey) is in the current round's miner list. [2](#0-1) 

**Transaction-Level Validation (Weaker):** [3](#0-2) 

This check uses an AND condition on negatives, which is logically equivalent to an OR on positives: a miner passes if they are in currentRound OR previousRound. The function recovers the TRANSACTION SENDER's public key, not the block producer's.

**Root Cause:**
The disconnect between who is validated at each layer creates an exploitable gap. Block validation ensures the legitimate block producer is authorized, but transaction execution validation allows transaction senders from the previous round. This permits a failed miner (removed from current round but present in previous round) to craft NextTerm transactions that:
1. Pass transaction pool validation (PreCheck allows previous round miners)
2. Get included by legitimate miners in their blocks
3. Pass block validation (legitimate miner is in current round)
4. Execute successfully (PreCheck allows the transaction sender from previous round)

**Critical Impact Location:** [4](#0-3) 

The `UpdateProducedBlocksNumberOfSender()` method credits the TRANSACTION SENDER (not the block producer) with a produced block, either in the next term's round information or directly in the election contract.

### Impact Explanation

**Direct Impact:**
- A failed miner who was removed from the current round (due to repeated failures or poor performance) can artificially inflate their block production statistics by submitting NextTerm transactions during term transitions
- Each successful exploit grants the attacker credit for 1 produced block in the election contract

**Election System Compromise:**
- The election contract uses block production statistics to determine miner rankings and re-election eligibility
- Artificially inflated production counts can keep failing miners in the validator set when they should be removed
- This undermines the meritocratic principle of the consensus mechanism

**Reward Misallocation:**
- Mining rewards and treasury distributions are calculated based on block production statistics
- The attacker receives undeserved rewards for blocks they did not actually produce
- Honest miners who actually produced blocks are proportionally disadvantaged

**Severity Justification:**
HIGH severity because it:
1. Directly compromises consensus integrity by allowing unauthorized consensus operations
2. Undermines the election system's fairness and accuracy
3. Results in concrete financial harm through reward misallocation
4. Can be repeatedly exploited at every term transition (typically every 7 days)

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must have been a legitimate miner in the previous round (round N-1)
- Attacker must have been removed/failed in the current round (round N) - this is the common case for failing miners
- Attacker needs basic blockchain interaction capability to craft and submit transactions

**Attack Complexity:**
- LOW complexity: Attacker needs to observe blockchain state to construct valid NextTerm input with correct round information
- The transaction structure is publicly visible from normal NextTerm transactions
- No special privileges or sophisticated techniques required

**Feasibility Conditions:**
- Attack window: Only available during term transitions when NextTerm is being executed
- Precondition: Attacker was in previous round but removed from current round (happens naturally when miners fail)
- The weaker PreCheck validation is always active during transaction execution

**Execution Practicality:**
1. Transaction pool validation uses `TransactionExecutionValidationProvider` which executes transactions to check validity
2. The attacker's transaction passes because PreCheck accepts previous round miners
3. Legitimate miners will include valid-looking transactions from the pool in their blocks
4. No special coordination or timing attacks required

**Detection Constraints:**
- The attack is difficult to detect because the transaction appears valid and passes all formal checks
- The transaction is properly signed and formatted
- Only forensic analysis comparing transaction senders with actual block producers would reveal the discrepancy

**Probability Assessment:**
HIGH likelihood because:
1. Attack preconditions occur naturally (miners being removed for failures)
2. Low technical barrier to execution
3. Clear economic incentive (stay elected, earn rewards)
4. Attack window occurs regularly (every term transition)
5. No defensive monitoring in place to detect this specific attack pattern

### Recommendation

**Code-Level Mitigation:**

Modify the PreCheck function to use the same strict validation as block-level validation - only allow miners in the current round:

```csharp
private bool PreCheck()
{
    TryToGetCurrentRoundInformation(out var currentRound);
    _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();
    
    // Only miners in the current round can execute consensus operations
    if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
        return false;
    
    return true;
}
```

**Additional Safeguards:**

1. Add explicit validation that transaction sender matches block producer for consensus operations: [5](#0-4) 

Add before line 28:
```csharp
// For consensus operations, transaction sender must be the block producer
var blockProducerPubkey = /* extract from consensus context */;
Assert(_processingBlockMinerPubkey == blockProducerPubkey, "Only block producer can submit consensus transactions");
```

2. Implement transaction pool filtering to reject consensus transactions from non-current-round miners

3. Add monitoring/events to log when consensus transactions are submitted by different addresses than the block producer

**Invariant Checks:**
- Assert: Transaction sender of NextTerm/NextRound/UpdateValue must be in current round's active miner list
- Assert: Transaction sender equals block producer for all consensus operations
- Assert: Block production credit is only awarded to miners who actually produced blocks

**Test Cases:**
1. Test that a miner from previous round (but not current) cannot execute NextTerm
2. Test that consensus transactions from non-block-producers are rejected
3. Test that block production credit is only awarded to actual block producers
4. Test term transition with mixed miner sets (some re-elected, some not)

### Proof of Concept

**Initial State:**
- Current term: T, Current round: 100 (last round of term T)
- Miner A is in round 100 (legitimate current miner)
- Miner B was in round 99 but is NOT in round 100 (failed/kicked out)
- It's time for term transition to term T+1

**Attack Steps:**

1. **Miner B observes blockchain state:**
   - Queries current round information
   - Identifies that term transition is imminent
   - Prepares NextTermInput with correct round 101 information (first round of term T+1)

2. **Miner B crafts malicious transaction:**
   - Creates NextTerm transaction with valid next round information
   - Signs transaction with Miner B's private key (not Miner A's)
   - Submits to transaction pool

3. **Transaction pool validation:**
   - `TransactionExecutionValidationProvider` executes the transaction
   - PreCheck is called: [6](#0-5) 
   - Miner B is NOT in currentRound (round 100): `!currentRound.IsInMinerList(MinerB)` = TRUE
   - Miner B IS in previousRound (round 99): `!previousRound.IsInMinerList(MinerB)` = FALSE  
   - Result: TRUE && FALSE = FALSE, PreCheck returns TRUE
   - Transaction ACCEPTED into pool

4. **Legitimate block production:**
   - Miner A produces block N (legitimately, as current round miner)
   - Includes Miner B's NextTerm transaction from pool
   - Signs block with Miner A's key

5. **Block validation:**
   - ValidateBeforeExecution checks block producer (Miner A) permissions
   - Miner A is in current round 100: PASSES [7](#0-6) 
   - Block ACCEPTED

6. **Transaction execution:**
   - NextTerm method called: [8](#0-7) 
   - ProcessConsensusInformation called
   - PreCheck validates Miner B (transaction sender): PASSES (Miner B in previous round)
   - ProcessNextTerm executes

7. **Undeserved credit awarded:**
   - UpdateProducedBlocksNumberOfSender called: [9](#0-8) 
   - Recovers Miner B's pubkey as sender
   - Miner B not in next term's round 101
   - Lines 30-34: Election contract updated with Miner B getting +1 RecentlyProducedBlocks
   - **ATTACK SUCCESS: Miner B credited for block they didn't produce**

**Expected vs Actual Result:**
- **Expected:** Only Miner A (actual block producer) gets block production credit
- **Actual:** Miner B (failed miner, transaction sender) gets block production credit
- **Success Condition:** Query election contract shows Miner B's RecentlyProducedBlocks incremented by 1, despite Miner B not being in current round and not producing any blocks

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L29-33)
```csharp
        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-31)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");

        State.RoundBeforeLatestExecution.Value = GetCurrentRoundInformation(new Empty());

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L20-35)
```csharp
    private void UpdateProducedBlocksNumberOfSender(Round input)
    {
        var senderPubkey = Context.RecoverPublicKey().ToHex();

        // Update produced block number of transaction sender.
        if (input.RealTimeMinersInformation.ContainsKey(senderPubkey))
            input.RealTimeMinersInformation[senderPubkey].ProducedBlocks =
                input.RealTimeMinersInformation[senderPubkey].ProducedBlocks.Add(1);
        else
            // If the sender isn't in miner list of next term.
            State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
            {
                Pubkey = senderPubkey,
                RecentlyProducedBlocks = 1
            });
    }
```
