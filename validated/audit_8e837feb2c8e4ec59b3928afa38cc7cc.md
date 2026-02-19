# Audit Report

## Title
Malicious Miner Can DoS Critical System Operations By Injecting Invalid Hex Strings Into Consensus Round Data

## Summary
A malicious current miner can inject invalid hex strings into the `RealTimeMinersInformation` dictionary when calling `NextRound` or `NextTerm`, causing unhandled exceptions in subsequent calls to `IsCurrentMiner`. This blocks critical operations including transaction fee claiming, resource token donation, and cross-chain indexing, effectively DoSing the entire system until the malicious round expires.

## Finding Description

The vulnerability exists in the interaction between consensus round updates and the `IsCurrentMiner` permission check used throughout the system.

**Vulnerable Execution Path:**

The `IsCurrentMiner` method is invoked to verify miner permissions for critical operations: [1](#0-0) 

This method calls `ConvertAddressToPubkey`, which iterates through public keys stored in `RealTimeMinersInformation.Keys`: [2](#0-1) 

For each key, the code invokes `ByteArrayHelper.HexStringToByteArray(k)` without any validation: [3](#0-2) 

The `Convert.ToByte(hex.Substring(i, 2), 16)` call will throw `FormatException` for invalid hex characters (e.g., "xyz") or `ArgumentOutOfRangeException` for odd-length strings after the "0x" prefix is removed.

**Root Cause - Input Validation Gap:**

When miners call `NextRound` or `NextTerm`, they provide input containing `RealTimeMinersInformation` as a protobuf map with string keys: [4](#0-3) 

The validation logic only checks round number correctness, InValue nullity, and mining order: [5](#0-4) [6](#0-5) 

**No validation exists to ensure the map keys are valid hexadecimal strings.**

The malicious round data is stored in state after passing validation: [7](#0-6) [8](#0-7) 

**Affected Critical Operations:**

Multiple system contracts rely on `IsCurrentMiner` for permission checks, all of which will fail with the stored malicious data:

1. **Transaction Fee Claiming:** [9](#0-8) [10](#0-9) 

2. **Resource Token Donation:** [11](#0-10) 

3. **Cross-Chain Indexing:** [12](#0-11) [13](#0-12) [14](#0-13) [15](#0-14) 

## Impact Explanation

**Severity: HIGH**

The vulnerability enables a system-wide denial-of-service attack affecting multiple critical operations:

1. **Economic Disruption**: All miners lose the ability to claim transaction fees via `ClaimTransactionFees`, resulting in direct financial loss and disrupting the economic incentive model that secures the network.

2. **Cross-Chain Communication Failure**: The `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal` operations fail completely, halting all cross-chain data synchronization. This is particularly severe for side chains that depend on parent chain coordination.

3. **Resource Token Economics Breakdown**: The `DonateResourceToken` mechanism fails, breaking the resource token distribution model.

4. **Network-Wide Impact**: Unlike typical vulnerabilities that affect only the attacker or specific users, this DoS impacts every participant in the network simultaneously.

5. **Extended Duration**: The DoS persists until the malicious round naturally expires based on the consensus round duration, which could be hours depending on network configuration.

6. **Validation Bypass**: The attack circumvents all existing validation logic, making it particularly dangerous as it appears valid to the consensus mechanism until the exception occurs during permission checks.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack is highly feasible due to several factors:

1. **Low Barrier to Entry**: The attacker only needs to be a current miner, which is achievable through the normal election process. A single compromised or malicious miner is sufficient.

2. **Simple Execution**: The attack requires minimal technical sophistication - simply construct a `NextRoundInput` or `NextTermInput` with one invalid hex string as a key (e.g., "xyz" or "abc123") in the `RealTimeMinersInformation` map.

3. **Validation Gap**: The permission check in `PreCheck` only verifies the sender is a current miner: [16](#0-15) 

4. **No Format Validation**: None of the validation providers check the hexadecimal format of map keys. The protobuf definition allows arbitrary string values: [17](#0-16) 

5. **Immediate Impact**: Once the malicious round is stored in state, any subsequent transaction requiring miner permission checks will fail immediately.

6. **Difficult Detection**: The malicious round data appears valid to existing validators and only causes failures when `IsCurrentMiner` is actually invoked, making proactive detection challenging.

## Recommendation

Add validation to ensure all keys in `RealTimeMinersInformation` are valid hexadecimal strings before storing the round data. This validation should be added to the `RoundTerminateValidationProvider` or a new dedicated validator:

```csharp
private ValidationResult ValidatePublicKeyFormat(Round round)
{
    foreach (var key in round.RealTimeMinersInformation.Keys)
    {
        if (string.IsNullOrWhiteSpace(key))
            return new ValidationResult { Message = "Empty public key in RealTimeMinersInformation" };
        
        var hex = key;
        if (hex.Length >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
            hex = hex.Substring(2);
            
        if (hex.Length == 0 || hex.Length % 2 != 0)
            return new ValidationResult { Message = $"Invalid hex length for public key: {key}" };
            
        foreach (char c in hex)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return new ValidationResult { Message = $"Invalid hex character in public key: {key}" };
        }
    }
    return new ValidationResult { Success = true };
}
```

This validator should be added to the validation pipeline in `ValidateBeforeExecution` for both `NextRound` and `NextTerm` behaviors: [18](#0-17) 

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousRound_WithInvalidHexKey_CausesDoS()
{
    // Setup: Get a valid round and modify it with invalid hex key
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Create malicious NextRoundInput with invalid hex key
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        RealTimeMinersInformation = 
        {
            ["xyz"] = new MinerInRound { Pubkey = "xyz", Order = 1 },  // Invalid hex
            // ... other valid miner data
        },
        // ... other valid round data
    };
    
    // Attacker (current miner) calls NextRound - should pass validation but doesn't
    await ConsensusStub.NextRound.SendAsync(maliciousInput);
    
    // Now IsCurrentMiner will throw exception for any address
    var isCurrentMiner = await ConsensusStub.IsCurrentMiner.CallAsync(SampleAccount.Addresses[0]);
    // This call will fail with FormatException when iterating through keys
    
    // Verify ClaimTransactionFees is now DoSed
    var claimResult = await TokenContractStub.ClaimTransactionFees.SendWithExceptionAsync(new TotalTransactionFeesMap());
    claimResult.TransactionResult.Error.ShouldContain("FormatException");
}
```

**Notes:**
- This vulnerability represents a critical validation gap in the consensus mechanism
- The mis-scoped privilege allows miners to inject data that breaks unrelated system operations
- Defense-in-depth principles require validating all user-controlled input, even from semi-trusted actors like miners
- The fix is straightforward and should be implemented immediately to prevent potential network disruption

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L111-118)
```csharp
    public override BoolValue IsCurrentMiner(Address input)
    {
        var pubkey = ConvertAddressToPubkey(input);
        return new BoolValue
        {
            Value = IsCurrentMiner(pubkey)
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L125-134)
```csharp
    private string ConvertAddressToPubkey(Address address)
    {
        if (!TryToGetCurrentRoundInformation(out var currentRound)) return null;
        var possibleKeys = currentRound.RealTimeMinersInformation.Keys.ToList();
        if (TryToGetPreviousRoundInformation(out var previousRound))
            possibleKeys.AddRange(previousRound.RealTimeMinersInformation.Keys);

        return possibleKeys.FirstOrDefault(k =>
            Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(k)) == address);
    }
```

**File:** src/AElf.Types/Helper/ByteArrayHelper.cs (L8-19)
```csharp
        public static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
                hex = hex.Substring(2);
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];

            for (var i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return bytes;
        }
```

**File:** protobuf/aedpos_contract.proto (L243-247)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** protobuf/aedpos_contract.proto (L458-462)
```text
message NextRoundInput {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L867-870)
```csharp
    public override Empty ClaimTransactionFees(TotalTransactionFeesMap input)
    {
        AssertSenderIsCurrentMiner();
        var claimTransactionExecuteHeight = State.ClaimTransactionFeeExecuteHeight.Value;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L897-906)
```csharp
    private void AssertSenderIsCurrentMiner()
    {
        if (State.ConsensusContract.Value == null)
        {
            State.ConsensusContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
        }

        Assert(State.ConsensusContract.IsCurrentMiner.Call(Context.Sender).Value, "No permission.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-915)
```csharp
    public override Empty DonateResourceToken(TotalResourceTokensMaps input)
    {
        AssertSenderIsCurrentMiner();
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-290)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-301)
```csharp
    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
        ReleaseIndexingProposal(input.ChainIdList);
        RecordCrossChainData(input.ChainIdList);
        return new Empty();
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```
