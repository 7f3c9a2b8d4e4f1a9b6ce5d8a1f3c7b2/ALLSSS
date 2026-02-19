### Title
Nothing-at-Stake: Miners Can Produce Blocks on Multiple Forks Without Detection or Penalty

### Summary
The `LibInformationValidationProvider.ValidateHeaderInformation()` function only validates that LIB (Last Irreversible Block) values do not decrease, but fails to detect or prevent miners from signing blocks on multiple conflicting forks at the same height. Despite documentation claiming malicious miners would be "voted out," there is no implementation of double-signing detection, evidence collection, or penalty enforcement, allowing miners to safely mine on all forks without consequences.

### Finding Description

**Exact Code Location:**
The vulnerability exists in the `ValidateHeaderInformation()` method [1](#0-0) 

**Root Cause:**
The validation logic only performs two checks:
1. Verifies that `providedRound.ConfirmedIrreversibleBlockHeight` and `providedRound.ConfirmedIrreversibleBlockRoundNumber` are not lower than `baseRound` values
2. Verifies that implied irreversible block height for the sender is not lower than the base round value

These checks ensure LIB monotonicity within a single chain but do NOT:
- Track which blocks a miner has already signed at a given height across different forks
- Collect evidence when a miner signs multiple conflicting blocks
- Compare the provided round against other potential blocks the miner might have signed
- Trigger any penalty or reporting mechanism for double-signing behavior

**Why Protections Fail:**
The validation is called during `ValidateBeforeExecution()` [2](#0-1)  where `LibInformationValidationProvider` is only added for `UpdateValue` behavior. The validation service [3](#0-2)  iterates through providers but each validation is independent and operates only against the `baseRound` from StateDb, not across fork branches.

The system's only "evil miner" detection mechanism [4](#0-3)  solely checks for missed time slots, not double-signing.

**Execution Path:**
1. Miner is elected and included in miner list
2. During network partition or selective broadcasting, miner produces Block A on Fork A at height H
3. Miner produces Block B on Fork B at height H (different block, same height)
4. Both blocks pass `ValidateConsensusBeforeExecution` [5](#0-4)  because each is validated against its own fork's state
5. Both blocks have compatible LIB values (same or higher than their respective fork's previous LIB)
6. No detection, evidence collection, or penalty occurs

### Impact Explanation

**Consensus Integrity Compromise:**
The Nothing-at-Stake problem fundamentally undermines the security model of delegated proof-of-stake consensus. The AElf documentation explicitly states [6](#0-5)  that malicious miners mining on multiple forks should be voted out, indicating this behavior is considered an attack. However, without detection or enforcement, this security property is not upheld.

**Concrete Harm:**
- **Delayed Finality**: Miners rationally produce blocks on all visible forks, preventing quick consensus convergence and delaying LIB advancement
- **Double-Spend Risk**: Before LIB advances, conflicting transactions can exist on different forks, enabling potential double-spend attacks
- **Economic Security Violation**: The system assumes miners have "skin in the game" and face penalties for malicious behavior, but this assumption is violated when miners can safely hedge across forks
- **Network Instability**: During network partitions or targeted attacks, the absence of penalties makes fork attacks more attractive and sustainable

**Affected Parties:**
- Users relying on transaction finality for high-value transfers
- Applications requiring fast settlement guarantees
- The overall network's consensus security and liveness properties

**Severity Justification:**
Critical - This violates a fundamental security assumption of the consensus mechanism. While the system eventually resolves to the longest chain [6](#0-5) , the window before resolution creates exploitable conditions for financial attacks.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an elected Core Data Center (miner), requiring either significant ELF token holdings or votes from token holders
- Attacker needs ability to broadcast different blocks to different network segments (achievable through strategic peering or during natural network issues)

**Attack Complexity:**
Low to Medium - Once elected as a miner, the attack is straightforward:
1. Monitor for fork conditions (network partition, competing valid blocks)
2. Sign blocks on multiple branches with compatible LIB values
3. Broadcast selectively to different network segments
4. No special cryptographic techniques or complex state manipulation required

**Feasibility Conditions:**
- Network partition occurs (can happen naturally during connectivity issues)
- OR attacker controls routing/peering to create artificial partition
- Multiple valid competing forks exist at similar heights
- LIB values on both forks are compatible (same or allowing monotonic increase)

**Detection/Operational Constraints:**
The code shows `EnsureTransactionOnlyExecutedOnceInOneBlock` [7](#0-6)  only prevents duplicate consensus transactions within the same block on the same fork, not cross-fork detection. The `ActualMiningTimes` tracking [8](#0-7)  only records mining on the executed canonical chain, not across forks.

**Probability Reasoning:**
Medium to High - Elected miners have strong rational incentives to maximize rewards by mining on all forks when no penalty exists. Natural network partitions occur periodically in distributed systems. The economic rationality of the attack combined with absence of detection makes exploitation likely among profit-maximizing miners.

### Recommendation

**1. Implement Double-Signing Evidence Collection:**
Add a mechanism to detect and record when a miner signs multiple blocks at the same height or round. This requires:
- Cross-fork block signature tracking outside individual chain state
- Evidence submission mechanism where any node can submit proof of double-signing
- Verification logic that validates the submitted evidence (both blocks properly signed by same miner at same height)

**2. Add Penalty Enforcement:**
Integrate with the Election contract's evil miner system:
```
// In a new validation provider or enhanced LibInformationValidationProvider:
- Check submitted evidence of double-signing
- If valid evidence exists, call ElectionContract.UpdateCandidateInformation
  with IsEvilNode = true
- Mark the miner in BannedPubkeyMap
- Slash or reduce the miner's rewards
```

**3. Enhance Validation Checks:**
Modify `LibInformationValidationProvider` to:
- Store a mapping of (miner_pubkey, height, round) -> block_hash for recent blocks
- During validation, check if the miner has already signed a different block at this height
- Reject blocks that constitute double-signing

**4. Add Invariant Checks:**
In `ValidateHeaderInformation`, add:
```
Assert(!HasAlreadySignedDifferentBlockAtHeight(pubkey, height, blockHash),
       "Miner has already signed a different block at this height");
```

**5. Test Cases:**
- Test that a miner producing two different blocks at same height is detected
- Test that evidence submission correctly marks miners as evil
- Test that slashing/penalty enforcement works correctly
- Test that legitimate fork scenarios (longest chain selection) still work properly

### Proof of Concept

**Required Initial State:**
- Network has elected miners: Miner_A, Miner_B, Miner_C, etc.
- Current chain at height H-1 with LIB at height H-10
- Network experiences partition creating Fork_A and Fork_B
- Both forks have same LIB values (height H-10, round R-5)

**Attack Steps:**
1. Miner_A is scheduled to produce block at height H
2. Miner_A creates Block_A for Fork_A:
   - Previous block hash: Fork_A's block at H-1
   - Consensus data with providedRound containing LIB height = H-10, round = R-5
   - Signs block with miner's private key
3. Miner_A creates Block_B for Fork_B:
   - Previous block hash: Fork_B's block at H-1  
   - Consensus data with providedRound containing same LIB height = H-10, round = R-5
   - Signs block with same miner's private key
4. Broadcasts Block_A to Fork_A network segment
5. Broadcasts Block_B to Fork_B network segment

**Expected Result (Current Behavior):**
- Block_A passes validation on Fork_A: `LibInformationValidationProvider` checks LIB H-10 >= base LIB H-10 ✓
- Block_B passes validation on Fork_B: `LibInformationValidationProvider` checks LIB H-10 >= base LIB H-10 ✓
- Both blocks are accepted and added to their respective forks
- No evil miner detection triggered
- No penalty applied to Miner_A
- Miner_A potentially earns rewards on both forks

**Actual Correct Behavior:**
- Second block should be rejected OR
- Evidence of double-signing should be recorded
- Miner_A should be marked as evil node
- Miner_A should be removed from miner list and penalized

**Success Condition:**
The attack succeeds if both blocks are accepted without any detection, evidence recording, or penalty enforcement - which is the current behavior as no such mechanisms exist in the codebase.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-104)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };

        // Skip the certain initial miner during first several rounds. (When other nodes haven't produce blocks yet.)
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
        }

        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };

        /* Ask several questions: */

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

        var service = new HeaderInformationValidationService(validationProviders);

        Context.LogDebug(() => $"Validating behaviour: {extraData.Behaviour.ToString()}");

        var validationResult = service.ValidateInformation(validationContext);

        if (validationResult.Success == false)
            Context.LogDebug(() => $"Consensus Validation before execution failed : {validationResult.Message}");

        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L16-26)
```csharp
    public ValidationResult ValidateInformation(ConsensusValidationContext validationContext)
    {
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** docs-sphinx/protocol/consensus.md (L81-81)
```markdown
In the systematic design, aelf defines that only one node generates blocks within a certain period. Therefore, it is unlikely for a fork to happen in an environment where mining nodes are working under good connectivity. If multiple orphan node groups occur due to network problems, the system will adopt the longest chain since that is 19 the chain that most likely comes from the orphan node group with largest number of mining nodes. If a vicious node mines in two forked Blockchains simultaneously to attack the network, that node would be voted out of the entire network.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```
