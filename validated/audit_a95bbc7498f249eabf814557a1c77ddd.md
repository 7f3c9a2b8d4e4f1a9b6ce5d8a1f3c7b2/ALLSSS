# Audit Report

## Title
Consensus Transaction Signer Mismatch Enables Continuous Block Limit Bypass

## Summary
A critical mismatch exists between the public key used during block validation and the public key used during state updates for the continuous block limit mechanism. The validation phase checks `ExtraData.SenderPubkey` (block signer) while the execution phase uses `Context.RecoverPublicKey()` (transaction signer). Two colluding miners can exploit this to bypass the continuous block production limit, allowing a single miner to produce unlimited consecutive blocks.

## Finding Description

The continuous block limit mechanism is designed to prevent any single miner from producing too many consecutive blocks. However, it suffers from a fundamental public key source mismatch:

**Validation Phase** uses the block signer's public key. The `ContinuousBlocksValidationProvider` validates the limit by comparing the stored pubkey against `validationContext.SenderPubkey`: [1](#0-0) 

This `SenderPubkey` is sourced from the consensus header extra data: [2](#0-1) 

The system validates that `ExtraData.SenderPubkey` matches the block's `SignerPubkey`: [3](#0-2) 

**Execution Phase** uses the transaction signer's public key. When processing consensus information, `PreCheck()` sets the pubkey from the transaction: [4](#0-3) 

The state update uses this transaction-recovered pubkey to manage the continuous block counter: [5](#0-4) 

**Missing Critical Validation:** While the system validates that `ExtraData.SenderPubkey` matches the block signer, it never validates that the transaction signer (`Context.RecoverPublicKey()`) matches `ExtraData.SenderPubkey`. The permission check only validates that both pubkeys are separately in the miner list: [6](#0-5) 

This allows an attack where:
1. Miner A creates block N with `BlockHeader.SignerPubkey = A`
2. Sets `ExtraData.SenderPubkey = A` (passes validation)
3. Includes a consensus transaction (UpdateValue/UpdateTinyBlockInformation) signed by Miner B
4. Validation checks the limit against A (from ExtraData)
5. Execution updates state using B (from transaction signature)
6. Counter resets because B ≠ A, bypassing the limit

The consensus methods are publicly callable, allowing any authorized miner to sign consensus transactions: [7](#0-6) [8](#0-7) 

## Impact Explanation

This vulnerability breaks a core consensus protection mechanism, enabling severe attacks:

1. **Consensus Centralization**: A single miner can produce unlimited consecutive blocks by alternating transaction signers with a colluding miner, completely defeating the purpose of the continuous block limit: [9](#0-8) 

2. **Transaction Censorship**: Extended control over block production allows systematic censorship of transactions

3. **MEV Extraction**: A monopoly on consecutive block production enables maximum extractable value across many blocks

4. **Reward Misallocation**: The colluding miners can unfairly monopolize block production rewards

5. **Chain Stability Risk**: Long sequences from a single producer increase reorganization vulnerability

The mechanism to detect and force `NextRound` when limits are exceeded is bypassed: [10](#0-9) 

## Likelihood Explanation

This vulnerability is **highly feasible** to exploit:

1. **Public Entry Points**: The consensus methods are public and callable by any authorized miner

2. **Realistic Preconditions**: Only requires two colluding miners in the active miner list. Since miners already coordinate for legitimate consensus operations, collusion is a realistic attack scenario.

3. **No Technical Barriers**: The normal mining flow signs transactions with the same key as the block, but nothing prevents including differently-signed transactions. Transaction construction shows independent From field assignment: [11](#0-10) 

4. **Cryptographic Validity**: Each signature (block and transaction) is independently valid. The block signature validation and transaction signature validation both pass—the missing check is their equality.

5. **Detection Difficulty**: The attack is not obvious from individual block inspection; it requires correlating block signers with transaction signers across blocks to detect.

## Recommendation

Add validation in the consensus contract to enforce that the transaction signer must match the block signer for consensus transactions. In `PreCheck()`, add:

```csharp
private bool PreCheck()
{
    TryToGetCurrentRoundInformation(out var currentRound);
    TryToGetPreviousRoundInformation(out var previousRound);

    _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();
    
    // NEW: Validate that transaction signer matches block signer
    // by comparing against the validated ExtraData.SenderPubkey
    var blockSigner = /* retrieve block signer from context */;
    Assert(_processingBlockMinerPubkey == blockSigner, 
        "Consensus transaction must be signed by block producer.");

    if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
        !previousRound.IsInMinerList(_processingBlockMinerPubkey))
        return false;

    return true;
}
```

Alternatively, during validation in `ValidateBeforeExecution`, ensure that `ExtraData.SenderPubkey` will be used during execution by storing it in state and using that value instead of recovering from the transaction signature.

## Proof of Concept

A complete PoC would require:
1. Two test miners (A and B) in the active miner list
2. Miner B signs an `UpdateValue` or `UpdateTinyBlockInformation` transaction
3. Miner A includes this transaction in their block and signs the block
4. Execute the block and observe that the continuous block counter resets instead of incrementing
5. Repeat with Miner A continuing to produce blocks while including transactions signed by B
6. Verify that Miner A can exceed the `MaximumTinyBlocksCount` limit (8 blocks) without triggering `NextRound`

**Notes**

The vulnerability relies on the architectural separation between block signing (performed by the block producer) and transaction signing (performed by the transaction creator). While the consensus extra data validation ensures `ExtraData.SenderPubkey` matches the block signer, there is no corresponding validation that the consensus transaction signer (recovered via `Context.RecoverPublicKey()`) matches this same public key. This mismatch allows the continuous block limit to be bypassed through collusion.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L16-19)
```csharp
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L17-17)
```csharp
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L32-32)
```csharp
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L321-321)
```csharp
        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L333-335)
```csharp
    /// <summary>
    ///     To prevent one miner produced too many continuous blocks.
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L108-112)
```csharp
    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L29-35)
```csharp
        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L72-83)
```csharp
    private Transaction GenerateTransaction(string methodName, IMessage parameter)
    {
        return new()
        {
            From = Context.Sender,
            To = Context.Self,
            MethodName = methodName,
            Params = parameter.ToByteString(),
            RefBlockNumber = Context.CurrentHeight,
            RefBlockPrefix = BlockHelper.GetRefBlockPrefix(Context.PreviousBlockHash)
        };
    }
```
