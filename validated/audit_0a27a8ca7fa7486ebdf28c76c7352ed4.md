# Audit Report

## Title
Missing Signature-to-Order Validation Allows Miners to Manipulate Next Round Mining Order

## Summary

The AEDPoS consensus mechanism fails to validate that miners' `SupposedOrderOfNextRound` values match their cryptographic signatures when processing `UpdateValue` transactions. A malicious miner can arbitrarily set their mining order to 1 (first position) in every round and manipulate other miners' positions, breaking consensus fairness and enabling MEV extraction.

## Finding Description

The vulnerability exists due to a critical validation gap in the `UpdateValue` transaction processing flow, where two execution paths diverge:

**Path 1 - Normal Block Production (Secure):**
When consensus data is generated during block production, the `ApplyNormalConsensusData` method correctly calculates mining order deterministically from the signature: [1](#0-0) 

**Path 2 - UpdateValue Transaction (Vulnerable):**
However, when a miner directly calls the public `UpdateValue` method, the `ProcessUpdateValue` method blindly accepts the order values from input without any cryptographic validation: [2](#0-1) 

Additionally, miners can manipulate OTHER miners' final orders through the unvalidated `TuneOrderInformation` dictionary: [3](#0-2) 

**Validation Gap:**
The `UpdateValueValidationProvider` only checks that `OutValue`, `Signature`, and `PreviousInValue` are properly filled, but does NOT validate the order fields: [4](#0-3) 

The `NextRoundMiningOrderValidationProvider` exists but is only applied to `NextRound` behavior, not `UpdateValue`: [5](#0-4) 

**Order Propagation to Next Round:**
The manipulated `FinalOrderOfNextRound` values directly determine the actual mining positions in the next round: [6](#0-5) 

Even the `RecoverFromUpdateValue` method used in validation only copies the order values without verifying their correctness: [7](#0-6) 

## Impact Explanation

**Consensus Integrity Breach:**
The vulnerability violates a fundamental consensus invariant - that mining order must be deterministically derived from cryptographic signatures to ensure randomness and fairness. This is the core security model of AEDPoS.

**MEV Extraction:**
Mining first in every round provides significant advantages:
- First access to profitable transactions in the mempool
- Control over transaction ordering within blocks for front-running/back-running opportunities
- Priority in including high-fee transactions
- Ability to observe other miners' consensus data before producing own block

**Centralization Risk:**
Multiple malicious miners can collude to claim sequential orders (1, 2, 3...) and push legitimate miners to later positions, creating mining cartels that dominate block production timing and transaction ordering.

**Economic Incentive Misalignment:**
The extra block producer is selected based on the first miner's signature, giving additional influence to whoever mines first: [8](#0-7) 

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an elected miner (achievable through normal governance/election)
- Must wait for their time slot in current round (guaranteed if they are a miner)
- No special network conditions or cryptographic breaking required

**Attack Execution:**
1. Craft `UpdateValueInput` with `SupposedOrderOfNextRound = 1`
2. Call the public `UpdateValue` method during their mining turn
3. The manipulated order is stored directly to state

**Detection Difficulty:**
Without validators explicitly checking the signature-to-order mathematical relationship, this manipulation appears as legitimate consensus data. The `BreakContinuousMining` function provides minimal mitigation by swapping positions to prevent consecutive extra block production: [9](#0-8) 

However, this doesn't prevent the core manipulation - a miner can still consistently be first or second in every round.

**Economic Rationality:**
The exploit cost is minimal (only transaction gas), while benefits accumulate over many rounds through MEV extraction and transaction fee advantages.

## Recommendation

Add cryptographic validation to the `UpdateValue` processing flow:

1. **Validate SupposedOrderOfNextRound in UpdateValueValidationProvider:**
   - Extract the signature from the provided round data
   - Calculate the expected order: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`
   - Verify that `SupposedOrderOfNextRound` matches this calculation
   - Reject the transaction if they don't match

2. **Restrict TuneOrderInformation manipulation:**
   - Add validation that miners can only tune their own order or provide cryptographic proof for tuning others
   - Ensure all final orders remain cryptographically bound to signatures

3. **Apply NextRoundMiningOrderValidationProvider to UpdateValue:**
   - Include order validation checks for UpdateValue behavior, not just NextRound

Example validation addition in `UpdateValueValidationProvider`:
```csharp
// After validating signature and out value
var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
var expectedOrder = GetAbsModulus(minerInRound.Signature.ToInt64(), minersCount) + 1;
if (minerInRound.SupposedOrderOfNextRound != expectedOrder)
    return new ValidationResult { Message = "Invalid SupposedOrderOfNextRound - does not match signature." };
```

## Proof of Concept

A malicious miner can exploit this vulnerability with the following transaction:

```csharp
// During their mining turn, a miner calls:
public void ExploitMiningOrder()
{
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateValidOutValue(),
        Signature = GenerateValidSignature(),
        PreviousInValue = GetPreviousInValue(),
        ActualMiningTime = Context.CurrentBlockTime,
        
        // EXPLOIT: Set arbitrary order to mine first in next round
        SupposedOrderOfNextRound = 1,  // Should be calculated from signature!
        
        // Can also manipulate other miners' positions
        TuneOrderInformation = {
            { "OtherMiner1Pubkey", 17 },  // Push competitor to last position
            { "OtherMiner2Pubkey", 16 }
        }
    };
    
    ConsensusContract.UpdateValue(maliciousInput);
    // Transaction succeeds - no validation checks the order matches the signature
}
```

The manipulated order values are stored to state and used in the next round, allowing the attacker to consistently mine first and gain MEV advantages.

---

**Notes:**
This vulnerability breaks the cryptographic randomness guarantee that is fundamental to AEDPoS consensus fairness. The two execution paths (normal block production vs UpdateValue transaction) must be unified to ensure consistent validation. The fix requires adding the missing signature-to-order validation check that already exists in `ApplyNormalConsensusData` to the `UpdateValue` validation flow.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-87)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L73-91)
```csharp
    private void BreakContinuousMining(ref Round nextRound)
    {
        var minersCount = RealTimeMinersInformation.Count;
        if (minersCount <= 1) return;

        // First miner of next round != Extra block producer of current round
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```
