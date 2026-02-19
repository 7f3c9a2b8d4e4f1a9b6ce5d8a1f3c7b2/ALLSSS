# Audit Report

## Title
Consensus Transaction Signer Mismatch Enables Continuous Block Limit Bypass

## Summary
A critical mismatch exists between the public key used during block validation and the public key used during state updates for the continuous block limit mechanism. The validation phase checks `ExtraData.SenderPubkey` (block signer) while the execution phase uses `Context.RecoverPublicKey()` (transaction signer). Two colluding miners can exploit this to bypass the continuous block production limit, allowing a single miner to produce unlimited consecutive blocks.

## Finding Description

The continuous block limit mechanism is designed to prevent any single miner from producing too many consecutive blocks. However, it suffers from a fundamental pubkey source mismatch:

**Validation Phase** uses the block signer's public key from consensus extra data. The `ContinuousBlocksValidationProvider` validates the limit by comparing `latestPubkeyToTinyBlocksCount.Pubkey` against `validationContext.SenderPubkey`, where `SenderPubkey` comes from `ExtraData.SenderPubkey`: [1](#0-0) 

This `SenderPubkey` is sourced from the consensus header extra data: [2](#0-1) 

The system validates that `ExtraData.SenderPubkey` matches the block's `SignerPubkey`: [3](#0-2) 

**Execution Phase** uses the transaction signer's public key recovered from the transaction signature. When processing consensus information, `PreCheck()` sets the pubkey from the transaction: [4](#0-3) 

The `RecoverPublicKey()` method recovers the public key from the transaction's cryptographic signature, not from the block header: [5](#0-4) 

The state update uses this transaction-recovered pubkey to manage the continuous block counter: [6](#0-5) 

**Missing Critical Validation:** While the system validates that `ExtraData.SenderPubkey` matches the block signer, it never validates that the transaction signer (`Context.RecoverPublicKey()`) matches `ExtraData.SenderPubkey`. The only checks are:
- Both pubkeys must be in the miner list (separately validated)
- `ExtraData.SenderPubkey` must match block signer

This allows an attack where:
1. Miner A creates block N with `BlockHeader.SignerPubkey = A` 
2. Sets `ExtraData.SenderPubkey = A` (passes validation)
3. Includes a consensus transaction (UpdateValue/UpdateTinyBlockInformation) signed by Miner B
4. Validation checks the limit against A (from ExtraData)
5. Execution updates state using B (from transaction signature)
6. Counter resets because B ≠ A, bypassing the limit

The consensus methods are publicly callable, allowing any authorized miner to sign consensus transactions: [7](#0-6) 

## Impact Explanation

This vulnerability breaks a core consensus protection mechanism, enabling severe attacks:

1. **Consensus Centralization**: A single miner can produce unlimited consecutive blocks by alternating transaction signers with a colluding miner, completely defeating the purpose of the continuous block limit documented in the code comments: [8](#0-7) 

2. **Transaction Censorship**: Extended control over block production allows systematic censorship of transactions

3. **MEV Extraction**: A monopoly on consecutive block production enables maximum extractable value across many blocks

4. **Reward Misallocation**: The colluding miners can unfairly monopolize block production rewards

5. **Chain Stability Risk**: Long sequences from a single producer increase reorganization vulnerability

The mechanism to detect and force `NextRound` when limits are exceeded is bypassed: [9](#0-8) 

## Likelihood Explanation

This vulnerability is **highly feasible** to exploit:

1. **Public Entry Points**: The consensus methods are public and callable by any miner: [10](#0-9) 

2. **Realistic Preconditions**: Only requires two colluding miners in the active miner list. Since miners already coordinate for legitimate consensus operations, this is a realistic attack scenario.

3. **No Technical Barriers**: The normal mining flow signs transactions with the same key as the block, but nothing prevents including differently-signed transactions. Transaction generation uses `Context.Sender`: [11](#0-10) 

4. **Cryptographic Validity**: Each signature (block and transaction) is independently valid. The block signature validation and transaction signature validation both pass—the missing check is their equality.

5. **Detection Difficulty**: The attack is not obvious from individual block inspection; it requires correlating block signers with transaction signers across blocks to detect.

## Recommendation

Add explicit validation that the transaction signer matches the block signer for consensus transactions. In `PreCheck()` method, add:

```csharp
private bool PreCheck()
{
    TryToGetCurrentRoundInformation(out var currentRound);
    TryToGetPreviousRoundInformation(out var previousRound);

    _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

    // NEW: Validate transaction signer matches expected block producer
    // This should match the SenderPubkey validated in ExtraData
    var expectedPubkey = /* retrieve from consensus extra data validation context */;
    if (_processingBlockMinerPubkey != expectedPubkey)
        return false;

    if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
        !previousRound.IsInMinerList(_processingBlockMinerPubkey))
        return false;

    return true;
}
```

Alternatively, add validation in `ContinuousBlocksValidationProvider` to check that the transaction recovered pubkey (available during execution) matches `SenderPubkey` from the validation context.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task ContinuousBlockLimit_BypassThroughTransactionSignerMismatch()
{
    // Setup: Initialize consensus with 2 miners (MinerA and MinerB)
    var minerA = SampleAccount.Accounts[0];
    var minerB = SampleAccount.Accounts[1];
    
    // MinerA produces blocks 1-N (up to limit)
    for (int i = 0; i < MaximumTinyBlocksCount; i++)
    {
        await ProduceBlock(minerA, minerA); // Block signer: A, Tx signer: A
    }
    
    // Now MinerA has reached the continuous block limit
    // Attempting one more block with normal flow should fail/force NextRound
    
    // ATTACK: MinerA produces block but includes transaction signed by MinerB
    var attackBlock = await ProduceBlock(
        blockSigner: minerA,     // Block signed by A
        txSigner: minerB         // Consensus tx signed by B
    );
    
    // The attack succeeds because:
    // 1. Validation checks ExtraData.SenderPubkey (A) - passes
    // 2. State update uses RecoverPublicKey() which returns B
    // 3. Counter sees B ≠ A, resets the counter
    // 4. MinerA can continue producing blocks indefinitely
    
    Assert.True(attackBlock.Success); // Should fail but passes
    
    // MinerA can now produce many more consecutive blocks
    for (int i = 0; i < MaximumTinyBlocksCount * 2; i++)
    {
        await ProduceBlock(minerA, i % 2 == 0 ? minerA : minerB);
    }
    
    // Verify MinerA produced far more than the limit by alternating signatures
    var actualConsecutiveBlocks = await GetConsecutiveBlockCount(minerA);
    Assert.True(actualConsecutiveBlocks > MaximumTinyBlocksCount);
}
```

## Notes

This is a critical consensus vulnerability that breaks a fundamental safety mechanism. The continuous block limit exists precisely to prevent the centralization risks that this bypass enables. The fix requires ensuring consistency between the public key used for validation (from block header) and the public key used for state updates (from transaction signature).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L17-19)
```csharp
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L17-17)
```csharp
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L29-32)
```csharp
        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L321-321)
```csharp
        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L333-336)
```csharp
    /// <summary>
    ///     To prevent one miner produced too many continuous blocks.
    /// </summary>
    /// <param name="minersCountInTheory"></param>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-364)
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
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L193-197)
```csharp
    public byte[] RecoverPublicKey()
    {
        return RecoverPublicKey(TransactionContext.Transaction.Signature.ToByteArray(),
            TransactionContext.Transaction.GetHash().ToByteArray());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-112)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }

    #endregion

    #region UpdateTinyBlockInformation

    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
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
