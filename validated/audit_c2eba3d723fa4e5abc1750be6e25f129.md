# Audit Report

## Title
Insufficient OutValue Validation Allows Miners to Bypass Consensus Participation Requirements

## Summary
The AEDPoS consensus validation only checks that `OutValue` and `Signature` are non-null and contain bytes, but never verifies that `OutValue` equals `Hash(InValue)` for the current round. This allows miners to submit arbitrary hash values (including `Hash.Empty`) to bypass proper consensus participation, manipulate next-round mining order, and gain mining credit without contributing to the secret-sharing mechanism.

## Finding Description

The AEDPoS consensus implements a commit-reveal scheme where miners commit to a secret value (`InValue`) by publishing its hash (`OutValue`), then reveal the secret in the next round. However, the validation logic contains a critical gap that breaks this security model.

**Insufficient Current Round Validation:**

The `UpdateValueValidationProvider.NewConsensusInformationFilled` method only performs superficial checks on `OutValue` and `Signature`: [1](#0-0) 

This validation never verifies that `OutValue` equals `HashHelper.ComputeFrom(InValue)` for the current round. The `InValue` is intentionally not included in `UpdateValueInput` (by design for the commit-reveal scheme), but this means current-round `OutValue` correctness is never cryptographically validated.

**Hash.Empty Bypass:**

`Hash.Empty` is defined as 32 zero bytes, which passes the `Value.Any()` check: [2](#0-1) 

More critically, when validating previous round values, if `previousInValue == Hash.Empty`, validation explicitly returns `true` without performing hash verification: [3](#0-2) 

**Direct Value Propagation Without Validation:**

During block validation, `RecoverFromUpdateValue` directly copies `OutValue` and `Signature` from miner-provided Round information without any cryptographic verification: [4](#0-3) 

These unvalidated values are then persisted to state via `ProcessUpdateValue`: [5](#0-4) 

**Mining Credit Without Proper Participation:**

The `SupposedOrderOfNextRound` is calculated directly from the miner-controlled `Signature` value using modulo arithmetic: [6](#0-5) [7](#0-6) 

Miners are identified as "having mined" based on `SupposedOrderOfNextRound != 0`: [8](#0-7) 

This affects reward distribution, as `GetMinedBlocks()` is sent to the Election contract: [9](#0-8) 

**Attack Execution:**
1. Malicious miner produces block with `UpdateValue` behavior
2. Sets `OutValue = Hash.Empty` and `Signature = chosen_value` in block header Round information
3. Validation passes (only checks non-null and has bytes)
4. State is updated with arbitrary values via `RecoverFromUpdateValue` and `ProcessUpdateValue`
5. `SupposedOrderOfNextRound` is calculated from the arbitrary signature
6. Miner is counted as having mined and influences next round position
7. In next round, miner submits `PreviousInValue = Hash.Empty` to bypass verification
8. Cycle repeats indefinitely

## Impact Explanation

**Consensus Integrity Violation:**

The AEDPoS consensus security model relies on a commit-reveal scheme for random number generation and fair miner ordering. By allowing miners to submit arbitrary `OutValue` and `Signature` values without cryptographic verification, the fundamental assumptions of the consensus mechanism are violated. Miners can fake participation without contributing valid secret values to the randomness pool, compromising the fairness and unpredictability of block production.

**Mining Order Manipulation:**

The next round mining order is deterministically calculated from signature values. By submitting arbitrary signatures, malicious miners can bias their position in future rounds, breaking the randomness that should govern mining schedules. While conflict resolution exists, miners can still influence their order towards preferred positions.

**Mining Credit Without Work:**

Miners receive credit for "actually mining" based on having non-zero `SupposedOrderOfNextRound`. This affects reward calculations sent to the Election contract via `TakeSnapshot`. Malicious miners gain unearned rewards while avoiding proper participation in the consensus secret-sharing mechanism.

**Severity:** High - This fundamentally breaks the consensus security model, enabling mining order manipulation and reward theft while undermining the commit-reveal randomness scheme.

## Likelihood Explanation

**Attacker Capabilities:**

The attacker must be a registered miner in the current round, achievable through normal election and staking mechanisms. Once registered, the attacker has full control over the block header contents they produce, including the Round information with `OutValue` and `Signature` fields.

**Attack Complexity:**

Low - The attack requires only modifying the `OutValue` and `Signature` fields in the block header's Round information to arbitrary values (e.g., `Hash.Empty` for `OutValue`, any chosen value for `Signature`). No cryptographic breaking or complex manipulation is needed.

**Execution Practicality:**

The validation flow is straightforward: [10](#0-9) [11](#0-10) 

The miner controls the `extraData.Round` included in the block header, and validation only performs superficial checks.

**Detection Difficulty:**

Miners using `Hash.Empty` values may appear as inactive or failed miners, making them difficult to distinguish from legitimate missed blocks without deep statistical analysis of behavior patterns across many rounds.

**Likelihood:** High - The attack is technically simple, practically executable by any miner, and difficult to detect through normal monitoring.

## Recommendation

Add cryptographic validation to `UpdateValueValidationProvider` to verify that the provided values are correctly computed:

1. **For current round validation:** Since `InValue` is not provided (by commit-reveal design), require that `OutValue` is NOT `Hash.Empty` and that `Signature` follows the expected calculation pattern based on previous round signatures. Add a check to reject `Hash.Empty` as an invalid commitment value.

2. **For previous round validation:** Remove the bypass at line 46 or add additional checks to ensure miners who consistently submit `Hash.Empty` as `PreviousInValue` are penalized or rejected.

3. **Add signature validation:** Verify that the provided `Signature` matches the expected calculation `CalculateSignature(InValue)` when `PreviousInValue` is revealed in the next round.

4. **Penalize invalid participation:** Track miners who repeatedly submit `Hash.Empty` values and mark them as malicious actors, similar to the existing evil miner detection mechanism.

## Proof of Concept

A proof of concept would require access to the AElf test infrastructure to:

1. Register as a miner in a test network
2. Modify the consensus command generation to produce blocks with `OutValue = Hash.Empty` and arbitrary `Signature` values
3. Submit these blocks and observe that validation passes
4. In the next round, submit `PreviousInValue = Hash.Empty` and observe validation bypass
5. Verify that `SupposedOrderOfNextRound` is set to a non-zero value
6. Confirm the miner is counted in `GetMinedMiners()` and affects reward distribution

The test would demonstrate that a miner can repeatedly participate with invalid values while maintaining mining credit and influencing mining order.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** src/AElf.Types/Types/Hash.cs (L13-14)
```csharp
        public static readonly Hash Empty = LoadFromByteArray(Enumerable.Range(0, AElfConstants.HashByteArrayLength)
            .Select(x => byte.MinValue).ToArray());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-17)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L215-215)
```csharp
            MinedBlocks = previousRound.GetMinedBlocks(),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-247)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L128-128)
```csharp
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L80-80)
```csharp
                validationProviders.Add(new UpdateValueValidationProvider());
```
