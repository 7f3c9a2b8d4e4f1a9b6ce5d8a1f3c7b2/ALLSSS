# Audit Report

## Title
Unvalidated Signature Field Allows Consensus Manipulation Through Mining Order Control

## Summary
The AEDPoS consensus contract accepts arbitrary `Signature` and `SupposedOrderOfNextRound` values in `UpdateValueInput` without cryptographic validation, allowing malicious miners to manipulate their mining position in subsequent rounds and influence extra block producer selection, breaking consensus fairness guarantees.

## Finding Description

The AEDPoS consensus mechanism contains a critical validation gap where the `Signature` field in `UpdateValueInput` is never validated against its expected calculated value during the UpdateValue transaction flow.

**Missing Validation**: The `UpdateValueValidationProvider` only verifies that the signature field is non-null and non-empty, without any cryptographic validation. [1](#0-0) 

**Honest Node Behavior**: When honest nodes produce blocks, they correctly calculate the signature using the deterministic function. [2](#0-1)  This calculated signature is then used to deterministically compute the mining order via modulo operation. [3](#0-2) 

**Vulnerable Processing**: During UpdateValue transaction processing, both the signature and the SupposedOrderOfNextRound are directly assigned from user input without any validation or recalculation. [4](#0-3) 

**Order Determination**: The next round's mining schedule uses `FinalOrderOfNextRound` values (initialized from `SupposedOrderOfNextRound`) to assign time slots, directly exposing the consensus to manipulation. [5](#0-4) 

**Extra Block Producer Selection**: The signature of the first miner is used to calculate the extra block producer order through the same modulo mechanism, making this selection manipulable as well. [6](#0-5) 

**Attack Vector**: A malicious miner can:
1. Choose their desired mining position (e.g., position 1 for maximum advantage)
2. Set `SupposedOrderOfNextRound = 1` in their `UpdateValueInput`
3. Provide any arbitrary `Signature` value (not validated)
4. Submit the UpdateValue transaction
5. Pass validation (only null-checks performed) [7](#0-6) 
6. Have their manipulated order accepted and used for next round scheduling

## Impact Explanation

This vulnerability breaks a **fundamental consensus security guarantee**: that mining order in each round is fairly and deterministically calculated from verifiable cryptographic data.

**Consensus Fairness Violation**: The AEDPoS protocol's security model assumes miners cannot choose their time slots, as order should be determined by unpredictable signature calculations. By allowing arbitrary order values, this assumption is completely violated.

**MEV and Transaction Ordering**: Earlier mining positions provide significant advantages in transaction ordering, allowing malicious miners to front-run transactions, extract maximum extractable value (MEV), and manipulate transaction execution order for profit.

**Extra Block Producer Manipulation**: The ability to influence extra block producer selection grants additional mining rewards and opportunities, further centralizing power to manipulators.

**Coordination Attacks**: Multiple colluding malicious miners can arrange consecutive time slots, enabling sophisticated attacks like transaction censorship, double-spend attempts (by controlling block production windows), and consensus disruption.

**Impact Assessment: HIGH** - This directly compromises blockchain consensus integrity, which is the foundational security layer upon which all other protocol guarantees depend.

## Likelihood Explanation

**Likelihood Assessment: HIGH**

**Accessible Entry Point**: UpdateValue is a public consensus method that any authorized miner can call during their time slot. [8](#0-7) 

**Minimal Prerequisites**: The attacker must be an authorized miner in the current round. This is precisely the threat model for analyzing Byzantine miner behavior - the scenario consensus protocols must defend against.

**Trivial Exploitation**: A miner needs only to modify their node software to:
- Set desired `SupposedOrderOfNextRound` value
- Provide any `Signature` value (arbitrary bytes)
- Submit the transaction

**No Detection Mechanism**: The validation system has no checks comparing provided signatures against expected calculated values, so manipulation is undetectable by the protocol.

**Repeatable**: The attack can be executed in every round, providing persistent advantage.

**Real-World Feasibility**: Unlike attacks requiring specific timing windows or rare conditions, this vulnerability is exploitable at will by any miner with modified software.

## Recommendation

**Implement Cryptographic Signature Validation**: Add validation in `UpdateValueValidationProvider` or `ProcessUpdateValue` to verify that the provided signature matches the expected value calculated from the previous round:

```csharp
// In UpdateValueValidationProvider or ProcessUpdateValue
var expectedSignature = validationContext.PreviousRound.CalculateSignature(
    validationContext.ExtraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue
);

if (!minerInRound.Signature.Equals(expectedSignature))
{
    return new ValidationResult { Message = "Invalid signature value." };
}
```

**Recalculate Order from Signature**: Instead of accepting `SupposedOrderOfNextRound` from input, recalculate it from the validated signature:

```csharp
// Remove direct assignment of SupposedOrderOfNextRound
// Instead, recalculate it
var sigNum = updateValueInput.Signature.ToInt64();
var minersCount = currentRound.RealTimeMinersInformation.Count;
minerInRound.SupposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**Validate Consistency**: Ensure the provided signature and order values are consistent with the deterministic calculation before accepting them.

## Proof of Concept

A malicious miner can demonstrate this vulnerability with the following test:

```csharp
// Test: Malicious miner manipulates mining order
[Fact]
public async Task MaliciousMiner_ManipulatesMiningOrder_Success()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(5);
    await InitializeConsensusWithMiners(miners);
    
    // Malicious miner chooses position 1 (first slot in next round)
    var maliciousMiner = miners[2]; // Currently position 3
    var desiredPosition = 1;
    
    // Create malicious UpdateValueInput
    var maliciousInput = new UpdateValueInput
    {
        OutValue = ComputeOutValue(), // Valid
        PreviousInValue = GetPreviousInValue(), // Valid
        Signature = Hash.FromString("arbitrary_malicious_signature"), // ARBITRARY
        SupposedOrderOfNextRound = desiredPosition, // DESIRED POSITION
        ActualMiningTime = Timestamp.Now,
        // ... other required fields
    };
    
    // Execute UpdateValue - should fail but doesn't
    var result = await maliciousMiner.UpdateValue(maliciousInput);
    result.Status.ShouldBe(TransactionResultStatus.Mined); // PASSES!
    
    // Verify manipulation succeeded
    var nextRound = await GetNextRoundInformation();
    var maliciousMinerInNextRound = nextRound.RealTimeMinersInformation[maliciousMiner.PublicKey];
    
    // Malicious miner got position 1 despite invalid signature
    maliciousMinerInNextRound.Order.ShouldBe(desiredPosition); // ATTACK SUCCEEDED
}
```

## Notes

This vulnerability exists because the AEDPoS contract trusts miners to provide correct signature and order values without verification. The separation between honest node calculation (which correctly computes signatures) and contract validation (which only checks non-null) creates an exploitable trust boundary. The fix requires enforcing the cryptographic relationship between signatures and mining order at the contract validation layer.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-247)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-122)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-80)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
```
