# Audit Report

## Title
Uncaught KeyNotFoundException in UpdateValueValidationProvider Causes Node DoS

## Summary
The `UpdateValueValidationProvider` performs dictionary accesses on `ProvidedRound.RealTimeMinersInformation` without `ContainsKey` checks. A malicious miner can craft consensus extra data with a `Round` object missing their own public key, triggering `KeyNotFoundException` that propagates as uncaught `ContractCallException`, causing validating nodes to crash or fail block processing.

## Finding Description

**Root Cause**: Multiple dictionary accesses in `UpdateValueValidationProvider` lack key existence validation.

**Vulnerable Code Locations**:

1. In `NewConsensusInformationFilled()`, the code directly accesses the dictionary without checking if the sender's public key exists: [1](#0-0) 

2. In `ValidatePreviousInValue()`, while line 40 checks `PreviousRound`, the code then accesses `extraData.Round` (which is `ProvidedRound`) without validation: [2](#0-1) 

**Attack Vector**: The `ConsensusValidationContext` distinguishes between `BaseRound` (from StateDb) and `ProvidedRound` (from block extra data): [3](#0-2) 

The `MiningPermissionValidationProvider` only validates `BaseRound`, not `ProvidedRound`: [4](#0-3) 

This allows a miner who is in `BaseRound` to craft malicious `ProvidedRound` data that passes initial validation but triggers the vulnerability.

**Exception Propagation Path**:

1. When `KeyNotFoundException` is thrown during contract execution, it's caught by `Executive.Execute()` and converted to `SystemError`: [5](#0-4) 

2. The view method `Call<T>` checks trace success and throws `ContractCallException` on failure: [6](#0-5) 

3. `ConsensusService.ValidateConsensusBeforeExecutionAsync()` has no exception handling: [7](#0-6) 

4. `ConsensusValidationProvider.ValidateBlockBeforeExecuteAsync()` has no exception handling: [8](#0-7) 

5. `BlockValidationService.ValidateBlockBeforeExecuteAsync()` has no exception handling: [9](#0-8) 

6. `ExecuteBlocksAsync()` only catches `BlockValidationException`, not `ContractCallException`: [10](#0-9) 

**Why Protections Fail**: `ContractCallException` inherits from `SmartContractBridgeException`: [11](#0-10) 

While `BlockValidationException` is a separate exception hierarchy: [12](#0-11) 

Since these are unrelated exception types, `ContractCallException` escapes the catch block.

## Impact Explanation

A malicious miner can craft blocks with consensus extra data containing a `Round` object that excludes their own public key from `RealTimeMinersInformation`. When other nodes attempt to validate such blocks:

- The uncaught `ContractCallException` propagates through the entire validation stack
- Node process terminates or block processing pipeline fails
- All full nodes and validators are affected simultaneously
- Network-wide consensus disruption occurs

**Severity**: Medium-to-High. While miner privileges are required, the impact is network-wide DoS affecting all nodes attempting to process the malicious block. The attack is easily detectable through exception logs, but prevention requires a code fix.

## Likelihood Explanation

**Attacker Capabilities**: Requires being a scheduled miner in the consensus rotation to produce blocks with custom consensus extra data.

**Attack Complexity**: Low. The attacker simply omits their own public key when constructing the `Round` object in the consensus extra data. The validation provider configuration in `ValidateBeforeExecution` adds `UpdateValueValidationProvider` for `UpdateValue` behavior: [13](#0-12) 

**Feasibility**: Moderate. Attacker needs miner privileges, but once obtained, the exploit is trivial to execute. The malformed data bypasses `MiningPermissionValidationProvider` since it only checks `BaseRound`.

## Recommendation

Add `ContainsKey` checks before all dictionary accesses in `UpdateValueValidationProvider`:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    // Add key existence check
    if (!validationContext.ProvidedRound.RealTimeMinersInformation.ContainsKey(validationContext.SenderPubkey))
        return false;
        
    var minerInRound =
        validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    return minerInRound.OutValue != null && minerInRound.Signature != null &&
           minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
}

private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

    // Add key existence check for ProvidedRound
    if (!extraData.Round.RealTimeMinersInformation.ContainsKey(publicKey)) return false;

    if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    if (previousInValue == Hash.Empty) return true;

    return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
}
```

Additionally, consider adding a catch block for `ContractCallException` in the validation pipeline or making validation providers return error results instead of throwing exceptions.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a malicious miner node that constructs consensus extra data with an `UpdateValue` behavior
2. In the `Round` object within the extra data, omitting the miner's own public key from `RealTimeMinersInformation`
3. Producing a block with this malformed consensus extra data
4. Observing that validating nodes crash or fail block processing with uncaught `ContractCallException`

The test would verify that:
- `MiningPermissionValidationProvider` passes (checks `BaseRound` only)
- `UpdateValueValidationProvider.NewConsensusInformationFilled()` throws `KeyNotFoundException`
- Exception propagates through validation stack uncaught
- Block processing fails with unhandled exception

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L29-30)
```csharp
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L40-45)
```csharp
        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L19-27)
```csharp
    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L148-152)
```csharp
        catch (Exception ex)
        {
            CurrentTransactionContext.Trace.ExecutionStatus = ExecutionStatus.SystemError;
            CurrentTransactionContext.Trace.Error += ex + "\n";
        }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L199-225)
```csharp
    public T Call<T>(Address fromAddress, Address toAddress, string methodName, ByteString args)
        where T : IMessage<T>, new()
    {
        var trace = AsyncHelper.RunSync(async () =>
        {
            var chainContext = new ChainContext
            {
                BlockHash = TransactionContext.PreviousBlockHash,
                BlockHeight = TransactionContext.BlockHeight - 1,
                StateCache = CachedStateProvider.Cache
            };

            var tx = new Transaction
            {
                From = fromAddress,
                To = toAddress,
                MethodName = methodName,
                Params = args
            };
            return await _transactionReadOnlyExecutionService.ExecuteAsync(chainContext, tx, CurrentBlockTime);
        });

        if (!trace.IsSuccessful()) throw new ContractCallException(trace.Error);

        var obj = new T();
        obj.MergeFrom(trace.ReturnValue);
        return obj;
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L119-149)
```csharp
    public async Task<bool> ValidateConsensusBeforeExecutionAsync(ChainContext chainContext,
        byte[] consensusExtraData)
    {
        var now = TimestampHelper.GetUtcNow();
        _blockTimeProvider.SetBlockTime(now, chainContext.BlockHash);

        var contractReaderContext =
            await _consensusReaderContextService.GetContractReaderContextAsync(chainContext);
        var validationResult = await _contractReaderFactory
            .Create(contractReaderContext)
            .ValidateConsensusBeforeExecution
            .CallAsync(new BytesValue { Value = ByteString.CopyFrom(consensusExtraData) });

        if (validationResult == null)
        {
            Logger.LogDebug("Validation of consensus failed before execution.");
            return false;
        }

        if (!validationResult.Success)
        {
            Logger.LogDebug($"Consensus validating before execution failed: {validationResult.Message}");
            await LocalEventBus.PublishAsync(new ConsensusValidationFailedEventData
            {
                ValidationResultMessage = validationResult.Message,
                IsReTrigger = validationResult.IsReTrigger
            });
        }

        return validationResult.Success;
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L58-78)
```csharp
    public async Task<bool> ValidateBlockBeforeExecuteAsync(IBlock block)
    {
        if (block.Header.Height == AElfConstants.GenesisBlockHeight)
            return true;

        var consensusExtraData = _consensusExtraDataExtractor.ExtractConsensusExtraData(block.Header);
        if (consensusExtraData == null || consensusExtraData.IsEmpty)
        {
            Logger.LogDebug($"Invalid consensus extra data {block}");
            return false;
        }

        var isValid = await _consensusService.ValidateConsensusBeforeExecutionAsync(new ChainContext
        {
            BlockHash = block.Header.PreviousBlockHash,
            BlockHeight = block.Header.Height - 1
        }, consensusExtraData.ToByteArray());
        if (!isValid) return false;

        return ValidateTransactionCount(block);
    }
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationService.cs (L35-45)
```csharp
    public async Task<bool> ValidateBlockBeforeExecuteAsync(IBlock block)
    {
        foreach (var provider in _blockValidationProviders)
            if (!await provider.ValidateBlockBeforeExecuteAsync(block))
            {
                Logger.LogDebug("Validate block before execution failed: {ProviderTypeName}", provider.GetType().Name);
                return false;
            }

        return true;
    }
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockchainExecutingService.cs (L40-70)
```csharp
    public async Task<BlockExecutionResult> ExecuteBlocksAsync(IEnumerable<Block> blocks)
    {
        var executionResult = new BlockExecutionResult();
        try
        {
            foreach (var block in blocks)
            {
                var blockExecutedSet = await ProcessBlockAsync(block);
                if (blockExecutedSet == null)
                {
                    executionResult.ExecutedFailedBlocks.Add(block);
                    return executionResult;
                }

                executionResult.SuccessBlockExecutedSets.Add(blockExecutedSet);
                Logger.LogInformation(
                    $"Executed block {block.GetHash()} at height {block.Height}, with {block.Body.TransactionsCount} txns.");

                await LocalEventBus.PublishAsync(new BlockAcceptedEvent { BlockExecutedSet = blockExecutedSet });
            }
        }
        catch (BlockValidationException ex)
        {
            if (!(ex.InnerException is ValidateNextTimeBlockValidationException)) throw;

            Logger.LogDebug(
                $"Block validation failed: {ex.Message}. Inner exception {ex.InnerException.Message}");
        }

        return executionResult;
    }
```

**File:** src/AElf.Kernel.SmartContract.Shared/ISmartContractBridgeContext.cs (L159-185)
```csharp
public class ContractCallException : SmartContractBridgeException
{
    //
    // For guidelines regarding the creation of new exception types, see
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
    // and
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
    //

    public ContractCallException()
    {
    }

    public ContractCallException(string message) : base(message)
    {
    }

    public ContractCallException(string message, Exception inner) : base(message, inner)
    {
    }

    protected ContractCallException(
        SerializationInfo info,
        StreamingContext context) : base(info, context)
    {
    }
}
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L14-41)
```csharp
[Serializable]
public class BlockValidationException : Exception
{
    //
    // For guidelines regarding the creation of new exception types, see
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
    // and
    //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
    //

    public BlockValidationException()
    {
    }

    public BlockValidationException(string message) : base(message)
    {
    }

    public BlockValidationException(string message, Exception inner) : base(message, inner)
    {
    }

    protected BlockValidationException(
        SerializationInfo info,
        StreamingContext context) : base(info, context)
    {
    }
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-83)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```
