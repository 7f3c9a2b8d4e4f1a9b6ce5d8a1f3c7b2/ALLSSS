### Title
Uncaught KeyNotFoundException in UpdateValueValidationProvider Causes Node DoS

### Summary
The `UpdateValueValidationProvider` contains dictionary accesses without `ContainsKey` checks that throw uncaught `KeyNotFoundException` exceptions. A malicious miner can provide consensus extra data with a `Round` object missing their own public key in `RealTimeMinersInformation`, causing validating nodes to crash or fail block processing. Note: The original hypothesis about `HashHelper.ComputeFrom` at line 48 is incorrect—that method cannot throw exceptions under normal circumstances. [1](#0-0) 

### Finding Description

**Root Cause**: Dictionary access without `ContainsKey` validation at multiple locations in `UpdateValueValidationProvider.cs`.

**Vulnerable Code Locations**:
1. Line 29-30 in `NewConsensusInformationFilled()`: Accesses `validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey]` without checking key existence [2](#0-1) 

2. Line 42 in `ValidatePreviousInValue()`: Accesses `extraData.Round.RealTimeMinersInformation[publicKey]` without checking key existence [3](#0-2) 

3. Line 45 in `ValidatePreviousInValue()`: Same dictionary access without validation [4](#0-3) 

**Note**: The function DOES check `PreviousRound` at line 40, but NOT `ProvidedRound` (extraData.Round) [5](#0-4) 

**Exception Propagation Path**:
1. `KeyNotFoundException` is caught by `Executive.Execute()` and set as `ExecutionStatus.SystemError` [6](#0-5) 

2. View method `Call<T>` checks trace success and throws `ContractCallException` if not successful [7](#0-6) 

3. `ConsensusService.ValidateConsensusBeforeExecutionAsync()` does NOT catch this exception [8](#0-7) 

4. `ConsensusValidationProvider.ValidateBlockBeforeExecuteAsync()` does NOT catch this exception [9](#0-8) 

5. `BlockValidationService.ValidateBlockBeforeExecuteAsync()` does NOT catch this exception [10](#0-9) 

6. `ExecuteBlocksAsync()` only catches `BlockValidationException`, NOT `ContractCallException` [11](#0-10) 

**Why Protections Fail**: `ContractCallException` (inherits from `SmartContractBridgeException`) is NOT a subclass of `BlockValidationException`, so it escapes the existing exception handler. [12](#0-11) [13](#0-12) 

### Impact Explanation

**Concrete Harm**: A malicious miner can craft blocks with consensus extra data containing a `Round` object that excludes their own public key from `RealTimeMinersInformation`. When other nodes attempt to validate such blocks, the uncaught exception propagates up the call stack, causing:
- Node crashes or unhandled exception termination
- Block processing pipeline failure
- Network-wide consensus disruption if multiple nodes affected

**Affected Parties**: All full nodes and validators attempting to process the malicious block.

**Severity**: Medium-to-High. While this requires miner privileges to execute, the impact is network-wide DoS. The attacker's own node may also be affected, providing some deterrence.

### Likelihood Explanation

**Attacker Capabilities**: Requires miner privileges (in scheduled rotation) to produce blocks with custom consensus extra data.

**Attack Complexity**: Low. Miner simply omits their own public key when constructing the `Round` object in consensus extra data.

**Feasibility Conditions**:
- Attacker must be a scheduled miner
- Earlier validation providers (`MiningPermissionValidationProvider`) only validate `BaseRound`, not `ProvidedRound`, so malformed data can reach vulnerable code [14](#0-13) 

**Detection**: Nodes will log unhandled exceptions, making attacks easily detectable but not preventable.

**Probability**: Moderate. Attacker needs miner privileges, but once obtained, exploit is trivial.

### Recommendation

**Immediate Fix**: Add `ContainsKey` checks before all dictionary accesses in `UpdateValueValidationProvider.cs`:

1. In `NewConsensusInformationFilled()` before line 30:
```csharp
if (!validationContext.ProvidedRound.RealTimeMinersInformation.ContainsKey(validationContext.SenderPubkey))
    return false;
```

2. In `ValidatePreviousInValue()` before line 42:
```csharp
if (!extraData.Round.RealTimeMinersInformation.ContainsKey(publicKey))
    return false;
```

**Additional Hardening**:
1. Add defensive exception catching in `ConsensusService.ValidateConsensusBeforeExecutionAsync()` to wrap `ContractCallException` as validation failure
2. Add integration test with malformed consensus data missing sender's public key
3. Consider validating `ProvidedRound` structure completeness early in validation pipeline

**Invariant to Enforce**: ProvidedRound.RealTimeMinersInformation MUST contain SenderPubkey before any field access.

### Proof of Concept

**Initial State**: Attacker has miner privileges in current round.

**Attack Steps**:
1. Attacker constructs consensus extra data for `UpdateValue` behavior
2. In the `Round` object, populate `RealTimeMinersInformation` dictionary but deliberately omit own public key
3. Include this malformed extra data in block header
4. Broadcast block to network

**Expected Result**: Validation passes and block is accepted.

**Actual Result**: 
- Other nodes execute `NewConsensusInformationFilled()` 
- Dictionary access at line 29-30 throws `KeyNotFoundException`
- Exception converts to `ContractCallException` 
- Exception propagates uncaught through validation stack
- Node crashes or fails block processing

**Success Condition**: Network nodes crash or log unhandled `ContractCallException` with stack trace showing `UpdateValueValidationProvider` as origin.

### Notes

**Important Clarification**: The original security question hypothesized that `HashHelper.ComputeFrom` at line 48 could throw exceptions. Investigation reveals this is incorrect—`HashHelper.ComputeFrom(Hash)` calls SHA256 which always returns 32 bytes, and `Hash.LoadFromByteArray()` only throws for non-32-byte inputs, so no exception is possible from that specific line under normal operation. [15](#0-14) [16](#0-15) 

However, the broader investigation revealed the dictionary access vulnerability described above, which represents a real DoS risk in the same validation function.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L40-40)
```csharp
        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L42-42)
```csharp
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L45-45)
```csharp
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L148-152)
```csharp
        catch (Exception ex)
        {
            CurrentTransactionContext.Trace.ExecutionStatus = ExecutionStatus.SystemError;
            CurrentTransactionContext.Trace.Error += ex + "\n";
        }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L221-221)
```csharp
        if (!trace.IsSuccessful()) throw new ContractCallException(trace.Error);
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

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockchainExecutingService.cs (L61-67)
```csharp
        catch (BlockValidationException ex)
        {
            if (!(ex.InnerException is ValidateNextTimeBlockValidationException)) throw;

            Logger.LogDebug(
                $"Block validation failed: {ex.Message}. Inner exception {ex.InnerException.Message}");
        }
```

**File:** src/AElf.Kernel.SmartContract.Shared/ISmartContractBridgeContext.cs (L159-159)
```csharp
public class ContractCallException : SmartContractBridgeException
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L15-15)
```csharp
public class BlockValidationException : Exception
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** src/AElf.Types/Extensions/ByteExtensions.cs (L64-70)
```csharp
        public static byte[] ComputeHash(this byte[] bytes)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(bytes);
            }
        }
```

**File:** src/AElf.Types/Types/Hash.cs (L49-58)
```csharp
        public static Hash LoadFromByteArray(byte[] bytes)
        {
            if (bytes.Length != AElfConstants.HashByteArrayLength)
                throw new ArgumentException("Invalid bytes.", nameof(bytes));

            return new Hash
            {
                Value = ByteString.CopyFrom(bytes)
            };
        }
```
