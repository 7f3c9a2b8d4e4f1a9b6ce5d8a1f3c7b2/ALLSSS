# Audit Report

## Title
PreviousInValue State Inconsistency Through Unconditional Overwrites in UpdateValue Processing

## Summary
The `PerformSecretSharing` function in the AEDPoS consensus contract allows any miner to unconditionally overwrite `PreviousInValue` fields for other miners without validation. This enables manipulation of signature calculations used during round transitions, compromising consensus integrity and random number generation.

## Finding Description

The vulnerability exists in the consensus update flow when secret sharing is enabled. When miners call the public `UpdateValue` method [1](#0-0) , the transaction is processed through `PerformSecretSharing`, which unconditionally overwrites `PreviousInValue` for any miners specified in the `MinersPreviousInValues` dictionary [2](#0-1) .

The vulnerability manifests in these unconditional write operations where no validation ensures that the provided `MinersPreviousInValues` are legitimate reconstructed values from the secret sharing protocol. A malicious miner can construct an `UpdateValueInput` with arbitrary values for other miners' `PreviousInValue` fields as allowed by the protobuf structure [3](#0-2) .

The validation logic only checks the sender's own `PreviousInValue`, not the values provided for other miners [4](#0-3) .

In contrast, a similar function `UpdateLatestSecretPieces` implements proper protection by only updating `PreviousInValue` when it's currently null or Hash.Empty [5](#0-4) .

The corrupted `PreviousInValue` is subsequently used during round transitions when `SupplyCurrentRoundInformation` fills in consensus data for miners who didn't produce blocks. The potentially corrupted `PreviousInValue` is retrieved [6](#0-5)  and used to calculate the signature [7](#0-6) , which directly affects consensus operations and random number generation.

## Impact Explanation

**Consensus Integrity Violation:** The corrupted `PreviousInValue` is used to calculate signatures for non-mining miners during round transitions. These signatures are critical components of the AEDPoS consensus mechanism and are used in random number generation. By manipulating these values, a malicious miner can influence consensus calculations.

**State Inconsistency:** Different miners can have inconsistent views of the consensus state within a round, as multiple miners producing blocks in the same round can repeatedly overwrite the same `PreviousInValue` fields, with the last writer winning. This violates the fundamental consensus invariant that all nodes should agree on the same state.

**Affected Parties:** All miners in the consensus set are potentially affected, particularly those who fail to produce blocks in a given round, as their signature calculations will be based on potentially corrupted data that wasn't cryptographically verified.

The severity is Medium-to-High as it undermines core consensus integrity, though exploitation requires miner-level privileges and primarily affects scenarios where miners don't produce blocks.

## Likelihood Explanation

**Reachable Entry Point:** The `UpdateValue` method is a public contract method callable by any miner during their designated block production time.

**Attacker Capabilities:** Any miner in the consensus set can construct a malicious `UpdateValueInput` with arbitrary `MinersPreviousInValues`. The protobuf structure explicitly allows a map of miner public keys to hash values.

**Execution Practicality:** The attack requires:
1. Attacker must be a valid miner (verified by `PreCheck` [8](#0-7) )
2. Attacker produces a block in the target round
3. Attacker constructs `UpdateValueInput` with fabricated `MinersPreviousInValues`
4. No validation prevents this during transaction processing

**One Transaction Per Block Protection:** While `EnsureTransactionOnlyExecutedOnceInOneBlock` [9](#0-8)  prevents multiple consensus transactions in a single block, it doesn't prevent the attack since different miners produce different blocks within the same round.

**Feasibility:** High - requires only being a valid miner (a semi-trusted role within the consensus set) to corrupt another miner's `PreviousInValue`. Detection is difficult as the overwrite happens during normal consensus operations.

## Recommendation

Add validation to `PerformSecretSharing` to only update `PreviousInValue` when it's currently null or Hash.Empty, similar to the protection in `UpdateLatestSecretPieces`:

```csharp
foreach (var previousInValue in input.MinersPreviousInValues)
    if (round.RealTimeMinersInformation.ContainsKey(previousInValue.Key) &&
        (round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue == Hash.Empty ||
         round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue == null))
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

Additionally, consider adding cryptographic verification of the reconstructed secret shares to ensure they were legitimately derived from the secret sharing protocol.

## Proof of Concept

A valid test demonstrating this vulnerability would:
1. Deploy the AEDPoS contract with secret sharing enabled
2. Initialize a round with multiple miners
3. Have MinerA call `UpdateValue` with a fabricated `MinersPreviousInValues` map containing arbitrary hash values for MinerB
4. Verify that MinerB's `PreviousInValue` was overwritten without validation
5. Trigger `NextRound` and observe that the corrupted `PreviousInValue` is used in signature calculations for MinerB

The test would show that arbitrary values can be written to other miners' consensus state without cryptographic validation, violating consensus integrity guarantees.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L191-191)
```csharp
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L199-199)
```csharp
                    signature = previousRound.CalculateSignature(previousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** protobuf/aedpos_contract.proto (L216-216)
```text
    map<string, aelf.Hash> miners_previous_in_values = 11;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```
