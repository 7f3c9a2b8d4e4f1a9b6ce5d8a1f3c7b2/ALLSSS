# Audit Report

## Title
Mining Order Manipulation via InValue Grinding in First Round of New Term

## Summary
The AEDPoS consensus mechanism allows miners to arbitrarily choose their InValue during the first round of each new term without cryptographic binding to previous round data. This enables miners to compute mining orders off-chain and select an InValue that places them in a favorable position for the second round, breaking the randomness property of consensus approximately every 7 days.

## Finding Description

The vulnerability exists in the interaction between round generation, signature calculation, and validation logic within the AEDPoS consensus contract.

**Root Cause - Hash.Empty Initialization:**
When generating the first round of a new term, all miners are initialized with `PreviousInValue = Hash.Empty`. [1](#0-0) 

The validation logic explicitly allows this empty value by returning `true` when `previousInValue == Hash.Empty`. [2](#0-1) 

**Why Cryptographic Binding Fails:**
During the first round of a new term, the signature calculation skips cryptographic binding to the previous round. The conditional check `!IsFirstRoundOfCurrentTerm(out _)` prevents execution of lines 72-109, which would normally bind the signature to previous round data. [3](#0-2) 

When this binding is skipped, the signature remains as the initial value calculated solely from miner-chosen values. [4](#0-3) 

**Grinding Attack Execution Path:**
The weak signature is directly used to determine the miner's position in the next round. [5](#0-4) 

Since a miner can compute this calculation off-chain for any InValue they choose (by trying different inputs to the off-chain InValue generation), they can select the InValue that produces their desired mining order. The InValue generation happens entirely off-chain via signing operations with no on-chain constraint forcing specific values. [6](#0-5) 

**Detection Resistance:**
The `IsFirstRoundOfCurrentTerm` check returns true during first round transitions, explicitly allowing this behavior. [7](#0-6) 

## Impact Explanation

This vulnerability directly undermines the consensus integrity of the AEDPoS mechanism:

1. **Consensus Randomness Broken**: The fundamental security property that mining order should be unpredictable and determined by verifiable randomness is violated. Miners can predictably choose their position rather than having it randomly assigned.

2. **Economic Advantages**: Early mining positions in a round can capture more valuable transactions and higher transaction fees. Miners can also avoid being selected as the extra block producer by choosing favorable orders.

3. **MEV Extraction Potential**: Predictable mining order enables sophisticated front-running attacks and Miner Extractable Value (MEV) exploitation, harming regular users.

4. **Coordinated Attack Vector**: Multiple colluding miners can coordinate their InValue selections to arrange favorable mining sequences across the entire network.

All network participants are affected as the integrity of the consensus mechanism - a critical security invariant - is compromised. The attack occurs every term change (approximately every 604,800 seconds or 7 days based on standard configuration).

## Likelihood Explanation

**Attacker Capabilities**: Any valid miner in the network can execute this attack without requiring special privileges, compromised keys, or coordination with other parties.

**Attack Complexity**: LOW - The attack requires only:
- Off-chain computation trying different InValue inputs (basic hashing operations)
- Calculating the resulting mining order for each candidate InValue
- Selecting and submitting the InValue that produces the desired order during the miner's time slot in the first round of a new term

**Feasibility**: The computational cost is negligible (trying hash combinations), the attack window is predictable (every term change), and there is no on-chain detection mechanism since any InValue is valid when `PreviousInValue = Hash.Empty`.

**Probability**: VERY HIGH - Every miner can exploit this vulnerability during every term change with zero on-chain cost and minimal off-chain computational resources.

## Recommendation

Implement cryptographic commitment for InValues even during the first round of new terms. Options include:

1. **Commit-Reveal Scheme**: Require miners to commit to their InValue for the new term during the last round of the previous term, then reveal during the first round. This prevents grinding since the commitment happens before miners know the full state.

2. **Derive from Previous Term State**: Bind the first-round InValue to verifiable previous term data (e.g., the last block hash of the previous term) using VRF or similar cryptographic primitives that prevent selective grinding.

3. **Secret Sharing Extension**: Extend the secret sharing mechanism to cover term transitions by having miners from the previous term contribute entropy that must be incorporated into first-round InValues of the new term.

The fix should ensure that even when `PreviousInValue = Hash.Empty`, the signature calculation cannot be freely manipulated by miners choosing arbitrary InValues.

## Proof of Concept

A proof of concept would involve:

1. Setting up a test network with multiple miners
2. During a term transition, having one miner iterate through different InValue candidates off-chain
3. For each candidate, computing: `signature = Hash(Hash(InValue) || InValue)` and `order = (|signature.ToInt64()| % minerCount) + 1`
4. Selecting an InValue that produces order=1 (first position)
5. Submitting this InValue during the miner's slot in the first round
6. Observing that the miner successfully obtains their chosen position in the second round

The attack succeeds because the validation at line 46 of UpdateValueValidationProvider.cs allows `Hash.Empty`, and the signature binding at lines 72-109 of AEDPoSContract_GetConsensusBlockExtraData.cs is skipped when `IsFirstRoundOfCurrentTerm` returns true.

## Notes

This vulnerability is present in the production consensus contract code and represents a design-level issue in how the first round of new terms handles InValue initialization. The comment "Should be careful during validation" in MinerList.cs line 34 suggests awareness of this edge case, but the current validation logic does not prevent exploitation. The issue affects consensus randomness - a critical security property - making it HIGH severity despite requiring the attacker to already be a miner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L34-35)
```csharp
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L67-70)
```csharp
        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L72-73)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L27-34)
```csharp
    private bool IsFirstRoundOfCurrentTerm(out long termNumber)
    {
        termNumber = 1;
        return (TryToGetTermNumber(out termNumber) &&
                TryToGetPreviousRoundInformation(out var previousRound) &&
                previousRound.TermNumber != termNumber) ||
               (TryToGetRoundNumber(out var roundNumber) && roundNumber == 1);
    }
```
