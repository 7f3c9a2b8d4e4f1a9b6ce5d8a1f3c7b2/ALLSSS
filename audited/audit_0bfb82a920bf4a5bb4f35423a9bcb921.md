# Audit Report

## Title
Incorrect Threshold Check in Secret Sharing Reconstruction Defeats Byzantine Fault Tolerance

## Summary
The AEDPoS consensus contract's secret sharing reconstruction logic incorrectly requires 100% of miners to provide decrypted pieces before attempting reconstruction, contradicting the 2/3 threshold defined by Shamir's Secret Sharing algorithm. This design flaw allows a single malicious miner to prevent forced revelation of their InValue by providing incomplete encrypted pieces, breaking the commit-reveal scheme's security guarantees and enabling manipulation of consensus randomness and mining order.

## Finding Description

The vulnerability exists in the `RevealSharedInValues` method where secret reconstruction is performed. The system correctly calculates a 2/3 threshold (`minimumCount`) for Shamir's Secret Sharing: [1](#0-0) 

However, the validation logic incorrectly requires ALL miners' decrypted pieces (100%) before attempting reconstruction: [2](#0-1) 

Despite this strict check, the actual secret reconstruction correctly uses only the 2/3 threshold: [3](#0-2) 

**Root Cause:** The check requires `DecryptedPieces.Count >= minersCount` instead of `DecryptedPieces.Count >= minimumCount`, contradicting Shamir's Secret Sharing mathematical properties which only require the threshold (2/3) for reconstruction.

**Why Protections Fail:**

1. **No EncryptedPieces Validation:** When miners submit their UpdateValue transactions, encrypted pieces are added without any completeness validation: [4](#0-3) 

2. **Empty PreviousInValue Allowed:** The UpdateValue validation explicitly permits `PreviousInValue = Hash.Empty`, bypassing forced revelation: [5](#0-4) 

3. **No Secret Sharing Enforcement:** Evil miner detection only tracks missed time slots based on OutValue being null, not secret sharing participation: [6](#0-5) 

**Attack Execution Path:**
1. **Round N:** Malicious miner produces their block via UpdateValue, but provides incomplete EncryptedPieces (e.g., encrypting pieces for only 2/3 of miners instead of all)
2. **Round N+1:** Only miners who received encrypted pieces can successfully decrypt and submit DecryptedPieces for the malicious miner
3. **Round N+1:** When `RevealSharedInValues` executes, the malicious miner's `DecryptedPieces.Count` is only 2/3 (below `minersCount`)
4. **Round N+1:** Secret reconstruction is skipped due to the incorrect 100% threshold check, even though 2/3 is mathematically sufficient
5. **Consequence:** The malicious miner's InValue remains unrevealed, allowing them to manipulate their signature calculation

## Impact Explanation

**HIGH Severity - Consensus Integrity Breach**

The vulnerability breaks the forced-reveal property of the secret sharing scheme, which is fundamental to ensuring fair and unpredictable consensus randomness.

**Concrete Harm:**

1. **Mining Order Manipulation:** The signature value determines the mining order for the next round. The signature is calculated from PreviousInValue: [7](#0-6) 

   This signature then determines the mining order through modulo arithmetic: [8](#0-7) 

   Without forced revelation, a malicious miner can avoid verification of their signature and potentially influence their mining position.

2. **Randomness Manipulation:** The miner can selectively choose whether to reveal their InValue based on whether the resulting mining order benefits them, breaking the commit-reveal scheme's unpredictability guarantee.

3. **Byzantine Fault Tolerance Defeated:** Shamir's Secret Sharing is explicitly designed to tolerate up to 1/3 Byzantine (malicious) miners by requiring only a 2/3 threshold for reconstruction. The incorrect 100% check effectively reduces the Byzantine tolerance to 0%, requiring all miners to be honest.

4. **Network-Wide Impact:** All network participants suffer from compromised consensus fairness, as the malicious miner gains unfair advantages in block production scheduling and rewards distribution.

## Likelihood Explanation

**HIGH Likelihood**

**Attacker Capabilities:** Any miner in the active validator set can execute this attack. No special privileges beyond being a validator are required.

**Attack Complexity:** LOW
- The attacker simply provides incomplete EncryptedPieces in their UpdateValue transaction
- No complex cryptographic manipulation or precise timing requirements
- The attack is undetectable at validation time since EncryptedPieces completeness is not checked during processing

**Feasibility Conditions:**
1. Attacker is an active miner (realistic precondition in any DPoS system)
2. Secret sharing is enabled, which is the standard operational mode for maintaining consensus randomness

**Detection Difficulty:** The attack is extremely difficult to detect because:
- Off-chain nodes cannot distinguish between network-delayed pieces and deliberately withheld pieces
- No on-chain slashing mechanism exists for incomplete secret sharing participation
- The only on-chain penalty mechanism tracks missed time slots (when OutValue is null), not secret sharing non-participation

**Probability:** The attack is straightforward to execute, provides concrete economic benefits through mining order manipulation, and carries minimal risk of detection or punishment.

## Recommendation

**Fix the threshold check to match Shamir's Secret Sharing requirements:**

Change line 36 in `AEDPoSContract_SecretSharing.cs` from:
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

To:
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This aligns the validation logic with the mathematical properties of Shamir's Secret Sharing, which only requires the threshold (2/3) for successful reconstruction, thereby restoring the intended Byzantine Fault Tolerance.

**Additional Hardening (Optional but Recommended):**
1. Add validation for EncryptedPieces completeness during UpdateValue processing
2. Implement slashing for miners who consistently provide incomplete EncryptedPieces
3. Consider making PreviousInValue revelation mandatory when secret sharing is enabled (disallow Hash.Empty)

## Proof of Concept

The vulnerability can be demonstrated by examining the code flow:

1. A miner creates an UpdateValue transaction with EncryptedPieces containing entries for only 10 out of 15 miners (67%)
2. The PerformSecretSharing method accepts and stores these incomplete pieces without validation
3. In the next round, only 10 miners can decrypt their pieces and submit DecryptedPieces
4. When RevealSharedInValues executes for this miner, it checks `DecryptedPieces.Count < 15` (minersCount), which evaluates to true (10 < 15)
5. The reconstruction is skipped despite having the mathematically sufficient threshold of 10 pieces (67% > 2/3 threshold)
6. The miner's PreviousInValue remains unrevealed, allowing them to set it to Hash.Empty or any value without cryptographic verification

This breaks the forced-reveal invariant that is fundamental to the security of the commit-reveal consensus scheme.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-36)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L45-46)
```csharp
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
