### Title
Insufficient OutValue Validation Allows Miners to Bypass Consensus Participation Requirements

### Summary
The `UpdateValueValidationProvider` only validates that `OutValue` is not null and contains bytes, but does not check if those bytes are all zeros (Hash.Empty) or verify that OutValue equals Hash(InValue). Miners can submit `Hash.Empty` or arbitrary hash values as their OutValue, bypass validation, be counted as having mined, and manipulate their next round mining order without properly participating in the consensus secret-sharing mechanism.

### Finding Description

**Root Cause:**

The validation in `NewConsensusInformationFilled()` checks `minerInRound.OutValue != null && minerInRound.OutValue.Value.Any()` [1](#0-0) , which only verifies that OutValue is not null and the byte array contains elements, but does not validate:
1. That OutValue is not Hash.Empty (32 zero bytes)
2. That OutValue was correctly computed as Hash(InValue)

The Hash type defines `Hash.Empty` as a valid Hash object containing 32 zero bytes [2](#0-1) , which passes the `!= null` check since it's a valid reference, and passes `Value.Any()` since it contains 32 bytes (even though they're all zeros).

**Validation Bypass:**

Additionally, `ValidatePreviousInValue()` explicitly bypasses hash verification when previousInValue equals Hash.Empty [3](#0-2) , returning true without checking if it hashes to the previously submitted OutValue. This allows a miner who submitted Hash.Empty as OutValue in round N to submit Hash.Empty as PreviousInValue in round N+1 and skip all verification.

**Missing Current Round Verification:**

While OutValue should be computed as `HashHelper.ComputeFrom(triggerInformation.InValue)` [4](#0-3) , there is no validation that verifies this relationship for the current round. The validation only checks the previous round's InValue-OutValue relationship, and even that can be bypassed with Hash.Empty.

**Mining Credit Determination:**

The system identifies miners who have mined by checking `OutValue != null` [5](#0-4)  and [6](#0-5) . A miner submitting Hash.Empty would be incorrectly counted as having mined.

**Next Round Order Manipulation:**

The signature value (which can also be set to arbitrary values passing the same weak validation) determines the next round mining order through modulo arithmetic [7](#0-6) , allowing miners to manipulate their future mining position.

### Impact Explanation

**Consensus Integrity Violation:**
- Miners can fake participation in consensus without properly contributing to the secret-sharing mechanism
- The AEDPoS consensus relies on commit-reveal scheme where OutValue commits to InValue, but this can be bypassed
- Random number generation that depends on OutValue contributions is compromised

**Mining Order Manipulation:**
- By submitting arbitrary Signature values (subject to same weak validation), miners can influence their `supposedOrderOfNextRound` calculation
- This breaks the fairness of mining order determination
- Miners can position themselves favorably in future rounds

**Mining Credit Without Work:**
- Miners are counted as having "actually mined" (OutValue != null) without properly participating
- This affects reward distribution and consensus participation metrics
- Breaks the assumption that miners with OutValue != null performed valid consensus work

**Severity:** Medium to High - While this requires being a registered miner, it fundamentally breaks consensus security assumptions and allows manipulation of mining order, which is critical for fair block production and network security.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a registered miner in the current round
- This is achievable through normal election/staking mechanisms

**Attack Complexity:**
- Low - Simply submit OutValue = Hash.Empty (or any arbitrary hash) in block header during UpdateValue behavior
- The consensus header information is constructed by the miner themselves
- No cryptographic breaking required

**Execution Practicality:**
- Highly practical - validation occurs in `ValidateBeforeExecution` for UpdateValue behavior [8](#0-7) 
- UpdateValueValidationProvider is the only additional validator for this behavior
- Miner controls the Round information in the header [9](#0-8) 

**Detection Difficulty:**
- Hash.Empty values might initially appear as failed/inactive miners
- Hard to distinguish from legitimate missed blocks without deep analysis
- Pattern would only emerge with statistical analysis of miner behavior

**Economic Rationality:**
- Cost: Risk of being detected and losing miner status
- Benefit: Manipulate mining order for favorable positions, reduce competition, potential reward manipulation
- Risk/reward ratio favorable for short-term exploitation

### Recommendation

**1. Add Hash.Empty Check:**
In `UpdateValueValidationProvider.NewConsensusInformationFilled()`, add explicit checks:
```csharp
return minerInRound.OutValue != null && minerInRound.Signature != null &&
       minerInRound.OutValue != Hash.Empty && minerInRound.Signature != Hash.Empty &&
       minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**2. Remove Hash.Empty Bypass:**
In `UpdateValueValidationProvider.ValidatePreviousInValue()`, remove the bypass at line 46 or add proper validation:
```csharp
if (previousInValue == Hash.Empty) 
    return previousOutValue == Hash.Empty; // Only allow if previous was also empty
```

**3. Add Zero-Bytes Check:**
Replace `.Any()` with a check that ensures bytes are not all zeros:
```csharp
minerInRound.OutValue.Value.Any(b => b != 0) // At least one non-zero byte
```

**4. Validate Current Round OutValue (Defense in Depth):**
While InValue is not available to validators (it's internal to block producer), add verification in `ApplyNormalConsensusData` that OutValue and Signature are valid hashes before processing, storing them only if they pass stricter validation.

**5. Test Cases:**
- Test that OutValue = Hash.Empty is rejected
- Test that OutValue with all-zero bytes is rejected  
- Test that PreviousInValue = Hash.Empty doesn't bypass validation inappropriately
- Test signature manipulation scenarios

### Proof of Concept

**Initial State:**
- Attacker is a registered miner in the current round
- Round N is in progress

**Attack Sequence:**

**Step 1 - Round N (Fake Mining):**
- Miner produces block with UpdateValue behavior
- In consensus header Round information, set:
  - `MinerInRound.OutValue = Hash.Empty` (32 zero bytes)
  - `MinerInRound.Signature = [chosen value for desired next round position]`
- Submit block

**Expected Validation:**
- `OutValue != null` → TRUE (Hash.Empty is not null reference)
- `OutValue.Value.Any()` → TRUE (has 32 bytes, all zeros)
- Validation passes ✓

**Result:** Miner is counted as having mined (OutValue != null), `FinalOrderOfNextRound` calculated from manipulated signature

**Step 2 - Round N+1 (Bypass Verification):**
- If miner mines again in round N+1, set:
  - `MinerInRound.PreviousInValue = Hash.Empty`
- Submit block

**Expected Validation:**
- `ValidatePreviousInValue` checks: `if (previousInValue == Hash.Empty) return true;`
- Hash verification at line 48 is never reached
- Validation passes ✓

**Result:** Miner bypasses the InValue-OutValue hash relationship check completely

**Success Condition:**
- Miner credited with mining in round N despite not computing valid OutValue = Hash(InValue)
- Miner's next round order influenced by their chosen signature value
- No validation failure occurs
- Consensus mechanism compromised

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L67-67)
```csharp
        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L175-175)
```csharp
        var notMinedMiners = currentRound.RealTimeMinersInformation.Values.Where(m => m.OutValue == null).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L153-153)
```csharp
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.OutValue != null)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** protobuf/aedpos_contract.proto (L303-310)
```text
message AElfConsensusHeaderInformation {
    // The sender public key.
    bytes sender_pubkey = 1;
    // The round information.
    Round round = 2;
    // The behaviour of consensus.
    AElfConsensusBehaviour behaviour = 3;
}
```
