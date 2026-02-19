# Audit Report

## Title
Commit-Reveal Scheme Bypass Through Selective PreviousInValue Omission Allows Mining Order Manipulation

## Summary
The AEDPoS consensus mechanism allows miners to intentionally omit their `PreviousInValue` during the reveal phase without validation failure or penalties. This breaks the commit-reveal protocol's security guarantee and enables miners to strategically choose between two different signature values after observing other miners' data, thereby manipulating their mining position in subsequent rounds for economic advantage.

## Finding Description

The vulnerability exists in the consensus validation logic where `PreviousInValue` omission is explicitly permitted without requiring secret sharing to be enabled.

**Root Cause:**

The `ValidatePreviousInValue()` method unconditionally accepts null or empty `PreviousInValue`: [1](#0-0) 

The design intentionally permits this behavior as evidenced by the comment in `ProcessUpdateValue`: [2](#0-1) 

**Attack Mechanism:**

When a miner omits `PreviousInValue`, the system generates a fallback value: [3](#0-2) 

This fallback value is used to calculate the miner's signature through XOR operations: [4](#0-3) 

The signature directly determines mining position for the next round: [5](#0-4) 

**Why Existing Protections Fail:**

Evil miner detection only penalizes miners who completely miss time slots (OutValue == null), not those who produce blocks but omit PreviousInValue: [6](#0-5) [7](#0-6) 

Secret sharing, which could force revelation through reconstruction, is optional: [8](#0-7) 

**Exploitation Path:**

1. In round N, miner M observes all finalized signatures from round N-1
2. M computes: `signature_A = previousRound.CalculateSignature(actualPreviousInValue)`
3. M computes: `signature_B = previousRound.CalculateSignature(fallbackValue)` 
4. M calculates resulting mining orders: `order_A = GetAbsModulus(signature_A.ToInt64(), minersCount) + 1` and `order_B` similarly
5. M chooses to reveal or omit based on which yields a more favorable position
6. No penalty is applied since M still produces a valid block with OutValue != null

## Impact Explanation

**HIGH Severity** is justified because:

**Consensus Integrity Violation:** The commit-reveal scheme's fundamental security property requires that participants cannot modify or selectively reveal their committed values after observing others' revelations. This implementation allows exactly that strategic behavior.

**Mining Order Manipulation:** Malicious miners gain systematic advantages:
- Earlier time slots may accumulate higher transaction fees
- Ability to influence transaction ordering more frequently
- Predictable positioning enables MEV-like extraction strategies
- Compounds over time for persistent economic advantage

**Affected Parties:**
- Honest miners face unfair competition and reduced expected rewards
- Network decentralization is undermined as strategic miners accumulate disproportionate influence
- Users experience degraded transaction ordering fairness

The vulnerability breaks a core consensus security mechanism without requiring special privileges, directly impacting economic fairness and decentralization guarantees.

## Likelihood Explanation

**HIGH Likelihood** due to:

**Low Attack Complexity:** Any active miner can modify off-chain trigger information or clear the InValue cache to omit PreviousInValue. The calculation to determine which strategy is favorable requires only basic arithmetic on publicly available round data.

**No Barriers to Entry:** 
- No special permissions beyond normal miner status
- No timing requirements or race conditions
- Works in standard operational conditions when secret sharing is disabled

**Undetectable:** The attack leaves no distinguishable trace since null PreviousInValue is treated as valid. No events, logs, or on-chain indicators differentiate legitimate omission from strategic manipulation.

**Economic Incentive:** Rational miners in competitive environments will exploit marginal advantages that compound over time. The absence of penalties creates a game-theoretic incentive for adoption.

**Realistic Preconditions:** Secret sharing is optional configuration. Many deployments may operate without it for performance or simplicity reasons, making this attack surface widely exposed.

## Recommendation

**Immediate Fix:** Enforce mandatory revelation when secret sharing is disabled by modifying the validation:

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true;

    var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    
    // NEW: Reject null PreviousInValue when secret sharing is disabled
    if ((previousInValue == null || previousInValue == Hash.Empty) && !IsSecretSharingEnabled())
        return false;
    
    if (previousInValue == Hash.Empty) return true;

    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
}
```

**Alternative Solution:** Make secret sharing mandatory rather than optional, ensuring all PreviousInValues can be reconstructed through the secret sharing mechanism, eliminating the attack surface entirely.

**Long-term:** Document the security model clearly - either secret sharing must be mandatory for mainnet, or implement alternative anti-gaming mechanisms like slashing for statistical anomalies in mining order selection patterns.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateMiningOrderByOmittingPreviousInValue()
{
    // Setup: Initialize consensus with 3 miners, secret sharing disabled
    var miners = new[] { "miner1", "miner2", "miner3" };
    await InitializeConsensusAsync(miners, enableSecretSharing: false);
    
    // Round N-1: Miner1 produces block with InValue
    var actualInValue = HashHelper.ComputeFrom("secret_value");
    await ProduceBlockAsync("miner1", actualInValue);
    var previousRound = await GetCurrentRoundAsync();
    
    // Round N: Miner1 computes both possible signatures
    var signatureWithReveal = previousRound.CalculateSignature(actualInValue);
    var fallbackValue = previousRound.RealTimeMinersInformation["miner1"].InValue ?? 
                        HashHelper.ComputeFrom("miner1" + Context.CurrentHeight);
    var signatureWithoutReveal = previousRound.CalculateSignature(fallbackValue);
    
    // Compute resulting mining orders
    var orderWithReveal = GetAbsModulus(signatureWithReveal.ToInt64(), miners.Length) + 1;
    var orderWithoutReveal = GetAbsModulus(signatureWithoutReveal.ToInt64(), miners.Length) + 1;
    
    // Strategic choice: Omit PreviousInValue if it yields better order
    var shouldOmit = orderWithoutReveal < orderWithReveal;
    
    // Execute attack: Produce block without revealing PreviousInValue
    await ProduceBlockAsync("miner1", newInValue: HashHelper.ComputeFrom("new_secret"), 
                           previousInValue: shouldOmit ? Hash.Empty : actualInValue);
    
    // Verify: No validation error, block accepted, and mining order manipulated
    var currentRound = await GetCurrentRoundAsync();
    Assert.True(currentRound.RealTimeMinersInformation["miner1"].OutValue != null);
    Assert.Equal(shouldOmit ? orderWithoutReveal : orderWithReveal,
                currentRound.RealTimeMinersInformation["miner1"].SupposedOrderOfNextRound);
    
    // Verify: No penalty applied (MissedTimeSlots unchanged)
    Assert.Equal(0, currentRound.RealTimeMinersInformation["miner1"].MissedTimeSlots);
}
```

## Notes

The vulnerability is confirmed through code analysis showing that the validation explicitly permits null `PreviousInValue` without enforcing secret sharing. The attack is feasible because miners have complete visibility into previous round signatures at decision time and can deterministically compute both possible outcomes. While the design intentionally allows PreviousInValue omission (as indicated by the comment), this permissiveness creates an exploitable game-theoretic weakness that undermines consensus fairness when secret sharing is disabled.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L42-46)
```csharp
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L96-107)
```csharp
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L91-93)
```csharp
        foreach (var minerInRound in currentRound.RealTimeMinersInformation)
            if (minerInRound.Value.OutValue == null)
                minerInRound.Value.MissedTimeSlots = minerInRound.Value.MissedTimeSlots.Add(1);
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
