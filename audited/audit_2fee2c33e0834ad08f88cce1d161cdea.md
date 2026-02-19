### Title
Commit-Reveal Scheme Bypass When Secret Sharing Is Disabled Allows Selective Withholding of Random Values

### Summary
The `ValidatePreviousInValue()` function unconditionally accepts null or Hash.Empty values for `PreviousInValue` without verifying that miners who committed an `OutValue` in the previous round reveal the corresponding `InValue`. When secret sharing is disabled via governance configuration, miners can exploit this to selectively withhold their reveals, breaking the cryptographic security of the commit-reveal randomness generation scheme and enabling bias in consensus randomness.

### Finding Description

The AEDPoS consensus mechanism uses a commit-reveal scheme for randomness generation where miners commit `OutValue = Hash(InValue)` in one round and must reveal the `InValue` in the next round. The validation logic in `ValidatePreviousInValue()` has critical flaws: [1](#0-0) [2](#0-1) 

These lines allow validation to pass when `PreviousInValue` is null or `Hash.Empty`, without checking whether the miner had previously committed an `OutValue` that must be revealed. The only actual verification occurs at line 48, but it's unreachable when `PreviousInValue` is null or empty. [3](#0-2) 

When secret sharing is enabled, this vulnerability is mitigated because other miners can reconstruct unrevealed values through Shamir's Secret Sharing: [4](#0-3) 

However, secret sharing is configurable via the governance-controlled Configuration Contract: [5](#0-4) [6](#0-5) 

When secret sharing is disabled, there is no compensating mechanism to enforce revelation. The block production code explicitly allows miners to omit `PreviousInValue`: [7](#0-6) 

When `PreviousInValue` is not provided, the consensus extra data generation uses `Hash.Empty`: [8](#0-7) 

This `Hash.Empty` value then passes validation (line 46 of UpdateValueValidationProvider), completing the bypass.

### Impact Explanation

**Consensus Integrity Compromise:**
- Miners can selectively choose whether to reveal their committed random values based on whether the outcome benefits them
- This breaks the fundamental cryptographic property of commit-reveal schemes: you cannot withhold or change your reveal after seeing others' values
- Random number generation used for miner ordering and consensus decisions becomes biased
- Miners gain unfair advantage by manipulating which values contribute to randomness

**Affected Parties:**
- All network participants relying on fair consensus randomness
- Other miners who honestly reveal their values
- Smart contracts and applications depending on unbiased random number generation for miner selection

**Severity Justification:**
The vulnerability breaks a core cryptographic security invariant of the consensus mechanism. While it requires secret sharing to be disabled, this is achievable through legitimate governance processes, making the attack practical if an adversary influences governance or if the feature is disabled for operational reasons.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner in consecutive rounds (achievable through normal staking/election)
- Requires secret sharing to be disabled via governance proposal, OR ability to influence governance to disable it

**Attack Complexity:**
- Low technical complexity: simply omit `PreviousInValue` when producing blocks
- No special transactions or contract exploits needed
- Attack is undetectable at the validation layer since the code explicitly allows it

**Feasibility Conditions:**
- Secret sharing must be disabled (configurable via Parliament governance)
- Attacker must control sufficient mining slots to impact randomness
- The configuration change is permanent until another governance action reverses it

**Probability Assessment:**
Medium likelihood. While secret sharing is likely enabled in production, the configuration can be changed through governance. An attacker with governance influence, or legitimate operational changes disabling the feature, would enable this exploit. The cost to become a miner and the governance influence needed creates moderate barriers but does not make the attack theoretical.

### Recommendation

**Immediate Fix:**
Modify `ValidatePreviousInValue()` to enforce revelation when the miner had committed an `OutValue` in the previous round:

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true;

    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    
    // If miner committed an OutValue, they MUST reveal (unless secret sharing reconstructed it)
    if (previousOutValue != null && previousOutValue != Hash.Empty)
    {
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        
        // Reject null or Hash.Empty when a commitment exists
        if (previousInValue == null || previousInValue == Hash.Empty)
            return false;
            
        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }

    return true;
}
```

**Invariant to Enforce:**
- When a miner has `OutValue != null && OutValue != Hash.Empty` in round N, they MUST provide valid `PreviousInValue` in round N+1 such that `Hash(PreviousInValue) == OutValue`
- This invariant should hold regardless of secret sharing configuration

**Additional Safeguards:**
1. Add governance constraints preventing secret sharing from being disabled without explicit security review
2. Implement monitoring to detect miners frequently producing blocks with `PreviousInValue = Hash.Empty`
3. Consider making secret sharing mandatory rather than optional

**Test Cases:**
1. Miner commits `OutValue` in round N, attempts to produce block with null `PreviousInValue` in round N+1 → should fail validation
2. Miner commits `OutValue` in round N, attempts to produce block with `Hash.Empty` in round N+1 → should fail validation
3. Miner commits `OutValue` in round N, provides valid `PreviousInValue` with correct hash → should pass validation
4. Test all scenarios with both secret sharing enabled and disabled

### Proof of Concept

**Initial State:**
- Secret sharing is disabled: `Configuration["SecretSharingEnabled"] = false`
- Miner Alice is active in round N and round N+1
- Other miners are honest and reveal their values

**Exploit Steps:**

1. **Round N - Commit Phase:**
   - Alice generates random `InValue_N = 0x1234...`
   - Alice computes `OutValue_N = Hash(InValue_N) = 0xabcd...`
   - Alice produces block with `OutValue_N` committed to state
   - State: `Rounds[N].RealTimeMinersInformation[Alice].OutValue = 0xabcd...`

2. **Round N+1 - Withhold Reveal:**
   - Alice observes other miners' revealed values and computed randomness
   - Alice decides withholding her value would bias outcome in her favor
   - Alice creates `UpdateValueInput` with:
     - `PreviousInValue = null` (or omits the field)
     - `OutValue = Hash(InValue_N+1)` for new round
     - Other required consensus data
   - Alice produces block

3. **Validation Phase:**
   - `ValidatePreviousInValue()` is called
   - Line 40: Alice was in previous round → continues
   - Line 42: `PreviousInValue == null` → **returns true (PASSES)**
   - No verification that `Hash(revealed) == OutValue_N` committed

4. **Result:**
   - Alice's block is accepted as valid
   - Alice successfully withheld `InValue_N` that she committed to
   - Random number generation proceeds without Alice's committed value
   - Consensus randomness is biased

**Expected vs Actual:**
- **Expected:** Validation should fail because Alice committed `OutValue_N` but didn't reveal corresponding `InValue_N`
- **Actual:** Validation passes, allowing Alice to break commit-reveal scheme

**Success Condition:**
Alice can repeatedly produce blocks in consecutive rounds while selectively choosing whether to reveal previous values, gaining unfair influence over consensus randomness without detection by the validation layer.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L42-42)
```csharp
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L48-48)
```csharp
        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L70-70)
```csharp
        var previousInValue = Hash.Empty; // Just initial previous in value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L56-78)
```csharp
    private bool IsSecretSharingEnabled()
    {
        if (State.ConfigurationContract.Value == null)
        {
            var configurationContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
            if (configurationContractAddress == null)
            {
                // Which means Configuration Contract hasn't been deployed yet.
                return false;
            }

            State.ConfigurationContract.Value = configurationContractAddress;
        }

        var secretSharingEnabled = new BoolValue();
        secretSharingEnabled.MergeFrom(State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = AEDPoSContractConstants.SecretSharingEnabledConfigurationKey
        }).Value);

        return secretSharingEnabled.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L15-15)
```csharp
    public const string SecretSharingEnabledConfigurationKey = "SecretSharingEnabled";
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```
