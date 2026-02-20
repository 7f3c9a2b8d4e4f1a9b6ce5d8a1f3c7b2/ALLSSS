# Audit Report

## Title
Consensus Mining Order Manipulation via Unverified Signature Field

## Summary
The AEDPoS consensus contract accepts arbitrary signature and mining order values from miners without cryptographic verification during the `UpdateValue` operation. This allows any authorized miner to deterministically control their mining position in subsequent rounds, violating consensus fairness and enabling continuous MEV extraction advantages.

## Finding Description

The AEDPoS consensus mechanism is designed to calculate mining orders deterministically from cryptographic signatures. The honest implementation calculates signatures by XORing the miner's in-value with all previous round signatures [1](#0-0) , then derives the mining order as `GetAbsModulus(signature.ToInt64(), minersCount) + 1` [2](#0-1) .

However, the validation provider only checks that the signature field is non-null and non-empty, without verifying correct calculation [3](#0-2) . During block processing, the system directly copies attacker-provided signature and order values without any verification or recalculation [4](#0-3) .

When the next round is generated, these manipulated order values directly determine mining time slots and positions [5](#0-4) . A malicious miner can exploit this by setting `SupposedOrderOfNextRound = 1` with arbitrary signature bytes, causing the system to assign them the first mining position in every subsequent round.

## Impact Explanation

**Critical Consensus Integrity Violation**: This breaks the core security guarantee that mining order is unpredictable and fairly determined. A malicious miner can deterministically control their position across all subsequent rounds, fundamentally compromising the consensus mechanism's fairness.

**Economic Advantages**: Earlier mining positions provide priority transaction selection for MEV capture, control over transaction ordering within blocks, first access to profitable arbitrage opportunities, and ability to front-run or sandwich other transactions.

**Persistent Exploitation**: The attacker can maintain mining position control indefinitely with zero additional cost, as the manipulation occurs in every block they produce. All other miners are disadvantaged as favorable time slots are monopolized.

## Likelihood Explanation

**High Likelihood**: Any authorized miner can execute this attack immediately with trivial effort. The only requirement is being an active miner in the current set - a realistic capability for the threat model. Technical complexity is extremely low - the attacker simply provides manipulated values in their `UpdateValue` transaction through the public method. No sophisticated cryptographic attacks or complex state manipulation required.

**Detection Difficulty**: The signature field appears valid (non-empty bytes), making the attack difficult to detect without specifically comparing expected vs. actual signature values. Strong economic incentive exists with zero cost to execute and ongoing MEV benefits.

## Recommendation

Add signature and order verification to `UpdateValueValidationProvider`:

1. Recalculate the expected signature using `previousRound.CalculateSignature(input.PreviousInValue)`
2. Verify that `input.Signature` matches the calculated signature
3. Derive the expected order as `GetAbsModulus(input.Signature.ToInt64(), minersCount) + 1`
4. Verify that `input.SupposedOrderOfNextRound` matches the derived order

The validation should reject any `UpdateValueInput` where the provided signature or order doesn't match the cryptographically computed values, ensuring miners cannot manipulate their mining positions.

## Proof of Concept

A proof of concept would involve:
1. Obtaining miner privileges in a test environment
2. Crafting an `UpdateValueInput` with:
   - `Signature = Hash.LoadFromByteArray(new byte[32])` (arbitrary non-empty bytes)
   - `SupposedOrderOfNextRound = 1`
   - Valid `OutValue` and `PreviousInValue`
3. Calling `UpdateValue` with this crafted input
4. Observing that validation passes
5. Verifying in the next round that the attacker has `Order = 1`
6. Repeating to demonstrate persistent control

The vulnerability is confirmed by examining that `ProcessUpdateValue` directly assigns the input values without recalculation, and `GenerateNextRoundInformation` uses these stored values to assign mining positions in the next round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-247)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```
