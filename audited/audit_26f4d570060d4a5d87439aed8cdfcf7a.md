### Title
Signature Malleability via InValue Grinding Allows Miners to Manipulate Next Round Order

### Summary
Miners can manipulate their `supposedOrderOfNextRound` by grinding through arbitrary `InValue` candidates before committing to an `OutValue`. The consensus mechanism lacks cryptographic verification of how `InValue` is generated, allowing miners to choose values that produce favorable mining orders in subsequent rounds. This violates miner schedule integrity and provides unfair advantages.

### Finding Description

The vulnerability exists in the consensus data flow across multiple components: [1](#0-0) 

The order for the next round is derived directly from the signature converted to an integer and taken modulo the miner count. The signature is calculated as: [2](#0-1) 

The signature is deterministically computed by XORing the `previousInValue` with all existing signatures from the previous round. Since the miner controls their `previousInValue` (revealed later), they control the signature and thus their order.

The only validation performed on `previousInValue` is: [3](#0-2) 

This merely checks that `Hash(previousInValue) == previousOutValue`, but provides no cryptographic verification that the `InValue` was generated correctly. While the client-side code generates `InValue` by signing data: [4](#0-3) 

There is **no on-chain enforcement** that miners follow this procedure. The `InValue` is treated as an arbitrary hash with no structural verification.

**Root Cause**: The consensus mechanism assumes miners honestly generate `InValue` using the prescribed signing procedure, but fails to cryptographically verify this assumption on-chain. Miners control both the `InValue` and `OutValue` selection as long as `Hash(InValue) = OutValue`, which they ensure by choosing them together.

### Impact Explanation

**Consensus Schedule Manipulation**: Miners can bias their mining order to position 1 (or any desired position), gaining:
- Higher block production frequency
- Priority in block production timing
- Increased mining rewards over honest miners
- Ability to delay or front-run specific miners

**Quantified Impact**: In a network with N miners, an honest miner has probability 1/N of getting any specific order. A malicious miner grinding ~N attempts (trivial computationally) can achieve near-certainty of obtaining their desired order, providing a significant unfair advantage.

**Affected Parties**: 
- All honest miners lose expected mining opportunities and rewards
- Network security is compromised as malicious miners gain disproportionate control
- Users experience potential transaction censorship or reordering

**Severity**: HIGH - This violates the core consensus invariant of "miner schedule integrity" and allows systematic gaming of the mining order assignment mechanism.

### Likelihood Explanation

**Attacker Capabilities**: Any miner (not requiring special privileges beyond being in the miner set) can execute this attack.

**Attack Complexity**: Low
1. Before producing a block in Round N, generate random `InValue` candidates (millions per second on standard hardware)
2. For each candidate, compute `OutValue = Hash(InValue)`
3. Calculate resulting signature: `signature = XOR(InValue, previousRoundSignatures)`
4. Calculate resulting order: `order = (signature % minersCount) + 1`
5. Select the `InValue` producing the most desirable order
6. Publish the corresponding `OutValue` in the Round N block
7. Later reveal the selected `InValue`

**Feasibility**: The attack is computationally trivial. Within the typical 4-second mining interval: [5](#0-4) 

A modern CPU can compute millions of hash operations, providing ample opportunity to find favorable values.

**Detection**: The attack is undetectable on-chain since the revealed `InValue` passes all validation checks. Off-chain detection through statistical analysis of order distribution would require long-term monitoring and could be masked by probabilistic variance.

**Economic Rationality**: The attack cost is negligible (electricity for extra computation) while the benefit is increased mining rewards and schedule control. The risk-reward ratio heavily favors exploitation.

### Recommendation

**Immediate Fix**: Implement cryptographic verification of `InValue` generation using a Verifiable Random Function (VRF) or require `InValue` to be a valid signature over deterministic data.

**Code-Level Mitigation**:
1. Add VRF-based InValue generation and verification:
   - Modify `GenerateInValueAsync` to use `ECVrfProve` on canonical SecretSharingInformation
   - Add validation in `UpdateValueValidationProvider` to verify VRF proof using `ECVrfVerify`
   - Store VRF proof alongside `InValue` for verification

2. Alternative: Require InValue to be a recoverable signature:
   - Modify validation to call `Context.RecoverPublicKey(InValue, SecretSharingInformation)` 
   - Verify recovered public key matches the miner's public key
   - This proves the InValue was generated by signing specific deterministic data

**Invariant Checks**:
- Assert that `InValue` cryptographically commits the miner to specific round data
- Verify that `InValue` generation is not miner-controllable beyond their private key

**Test Cases**:
- Test that two InValues for the same round data produce different OutValues (should fail after fix)
- Test that InValue verification rejects arbitrary values
- Test that InValue verification accepts only properly generated values
- Statistical tests showing order distribution is uniform after fix

### Proof of Concept

**Initial State**: 
- Network with 5 miners in Round N-1
- Malicious miner preparing to produce block in Round N
- Previous round signatures are known: `[sig1, sig2, sig3, sig4, sig5]`

**Attack Steps**:

1. **Grinding Phase** (before producing Round N block):
```
for i = 1 to 1,000,000:
    candidate_InValue = RandomHash()
    candidate_OutValue = Hash(candidate_InValue)
    
    // Calculate what signature this would produce in Round N
    candidate_signature = XOR(candidate_InValue, XOR(sig1, sig2, sig3, sig4, sig5))
    
    // Calculate what order this would produce for Round N+1
    candidate_order = (candidate_signature % 5) + 1
    
    if candidate_order == 1:  // Desired: position 1
        selected_InValue = candidate_InValue
        selected_OutValue = candidate_OutValue
        break
```

2. **Commit Phase** (Round N block production):
   - Produce block with `OutValue = selected_OutValue`
   - This passes validation as it's just a hash commitment

3. **Reveal Phase** (Round N or later):
   - Reveal `previousInValue = selected_InValue`
   - Validation checks: `Hash(selected_InValue) == selected_OutValue` ✓ (passes)
   - Signature calculated: `XOR(selected_InValue, previous_signatures)`
   - Order assigned: position 1 (attacker's desired position)

**Expected vs Actual**:
- Expected: Order assignment should be unpredictable, uniform distribution (1/5 chance of any position)
- Actual: Attacker achieves desired position with near certainty through grinding

**Success Condition**: Malicious miner consistently obtains favorable orders (e.g., position 1) significantly more often than the expected 20% probability, demonstrating successful manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-74)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L44-48)
```csharp
        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L186-191)
```csharp
    private async Task<Hash> GenerateInValueAsync(IMessage message)
    {
        var data = HashHelper.ComputeFrom(message.ToByteArray());
        var bytes = await _accountService.SignAsync(data.ToByteArray());
        return HashHelper.ComputeFrom(bytes);
    }
```
