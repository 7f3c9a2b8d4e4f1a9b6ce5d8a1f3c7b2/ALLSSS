### Title
Malicious Miner Can DoS Critical System Operations By Injecting Invalid Hex Strings Into Consensus Round Data

### Summary
A malicious current miner can inject invalid hex strings into the `RealTimeMinersInformation` dictionary when calling `NextRound` or `NextTerm`, causing unhandled exceptions in subsequent calls to `IsCurrentMiner`. This blocks critical operations including transaction fee claiming, resource token donation, and cross-chain indexing, effectively DoSing the entire system until the malicious round expires.

### Finding Description

The vulnerability exists in the interaction between consensus round updates and the `IsCurrentMiner` permission check: [1](#0-0) 

The `IsCurrentMiner` method calls `ConvertAddressToPubkey`, which iterates through miner public keys stored in `RealTimeMinersInformation.Keys`: [2](#0-1) 

For each key `k`, the code calls `ByteArrayHelper.HexStringToByteArray(k)` at line 133. This method performs no validation and will throw exceptions for invalid hex strings: [3](#0-2) 

The `Convert.ToByte(hex.Substring(i, 2), 16)` at line 16 throws `FormatException` for invalid hex characters (e.g., "xyz") or `ArgumentOutOfRangeException` for odd-length strings (e.g., "abc").

**Root Cause**: When miners call `NextRound` or `NextTerm`, they provide a `NextRoundInput` or `NextTermInput` containing `RealTimeMinersInformation`: [4](#0-3) [5](#0-4) 

The protobuf definition allows arbitrary strings as keys and values: [6](#0-5) [7](#0-6) 

**Why Protections Fail**: The validation logic only checks round number, InValue nullity, and mining order - it never validates pubkey string format: [8](#0-7) [9](#0-8) 

**Affected Operations**: Multiple critical system contracts call `IsCurrentMiner` for permission checks:

Token contract for fee claiming: [10](#0-9) [11](#0-10) 

Cross-chain contract for indexing: [12](#0-11) [13](#0-12) [14](#0-13) 

### Impact Explanation

**Direct Operational Impact**: The DoS affects multiple critical system operations:

1. **Transaction Fee Claiming**: Miners cannot claim their transaction fees via `ClaimTransactionFees`, causing economic disruption and loss of miner income
2. **Resource Token Donation**: The `DonateResourceToken` operation fails, breaking the resource token economic model
3. **Cross-Chain Indexing**: Cross-chain block data cannot be proposed or released via `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal`, halting all cross-chain communication
4. **Genesis Contract Operations**: Contract deployment and updates requiring miner permission fail

**Severity Justification**: HIGH because:
- Breaks consensus-critical operations (cross-chain indexing required for side chain functionality)
- Disrupts economic incentives (fee claiming blocked for ALL miners, not just attacker)
- Affects entire network until malicious round expires (could be hours depending on round duration)
- Relatively low cost to execute (only requires being a current miner)

### Likelihood Explanation

**Attacker Capabilities**: Attacker must be a current miner authorized to call `NextRound` or `NextTerm`. This is a realistic precondition as:
- Miners are selected through the election process
- A single malicious or compromised miner is sufficient
- The attack requires no special permissions beyond current miner status

**Attack Complexity**: Low - the attacker simply:
1. Constructs a valid `NextRoundInput` or `NextTermInput` 
2. Adds one entry to `RealTimeMinersInformation` with an invalid hex key (e.g., "xyz" or "abc")
3. Calls `NextRound` or `NextTerm`
4. The malformed data passes all validations and gets stored

**Feasibility**: The attack is highly practical because:
- Permission check at line 328 of `AEDPoSContract_ProcessConsensusInformation.cs` only verifies the sender is a current miner
- No validation on pubkey string format exists in any validation provider
- Protobuf allows arbitrary string values
- The impact is immediate once any transaction requires miner permission check

**Detection Constraints**: The attack is difficult to detect proactively because:
- The malicious round data appears valid to all existing validators
- The DoS only manifests when `IsCurrentMiner` is called
- No logs or events warn of malformed pubkey strings in round data

### Recommendation

**Immediate Fix**: Add pubkey format validation in the consensus round validation logic:

1. In `RoundTerminateValidationProvider.ValidationForNextRound` or a new dedicated validator, add:
```csharp
// Validate all pubkey strings in RealTimeMinersInformation
foreach (var minerInfo in extraData.Round.RealTimeMinersInformation)
{
    if (!IsValidHexString(minerInfo.Key) || !IsValidHexString(minerInfo.Value.Pubkey))
    {
        return new ValidationResult { Message = "Invalid pubkey hex format in round information." };
    }
}

private bool IsValidHexString(string hex)
{
    if (string.IsNullOrEmpty(hex)) return false;
    if (hex.Length % 2 != 0) return false; // Must be even length
    
    foreach (char c in hex)
    {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}
```

2. Alternatively, wrap the `ByteArrayHelper.HexStringToByteArray` call in a try-catch in `ConvertAddressToPubkey` and return null on exception:
```csharp
try
{
    return possibleKeys.FirstOrDefault(k =>
        Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(k)) == address);
}
catch (Exception)
{
    return null; // Invalid hex in miner list
}
```

**Invariant to Enforce**: All pubkey strings in `RealTimeMinersInformation` must be valid even-length hexadecimal strings matching the pattern `^[0-9a-fA-F]*$` with `length % 2 == 0`.

**Test Cases**:
1. Attempt to call `NextRound` with odd-length pubkey in `RealTimeMinersInformation` - should fail validation
2. Attempt to call `NextTerm` with invalid hex characters in pubkey - should fail validation
3. After fixing, verify `IsCurrentMiner` never throws exceptions even with previously-stored malformed data

### Proof of Concept

**Initial State**:
- Attacker is a current miner with authority to call `NextRound`
- Current round number is N
- Other miners expect normal round transitions

**Attack Steps**:

1. Attacker constructs malicious `NextRoundInput`:
```protobuf
NextRoundInput {
  round_number: N+1
  real_time_miners_information: {
    "xyz": { // Invalid hex string as key
      pubkey: "xyz"
      order: 1
      expected_mining_time: <valid_timestamp>
    }
    // ... other valid miners
  }
  term_number: <current_term>
  // ... other valid fields
}
```

2. Attacker calls `AEDPoSContract.NextRound(malicious_input)`

3. Input passes validation because no validator checks pubkey hex format

4. Malicious round data stored in `State.Rounds[N+1]`

5. Any miner attempts to claim transaction fees: `TokenContract.ClaimTransactionFees(...)`

6. Token contract calls `IsCurrentMiner(miner_address)`

7. `ConvertAddressToPubkey` iterates through `RealTimeMinersInformation.Keys` including "xyz"

8. `ByteArrayHelper.HexStringToByteArray("xyz")` throws `FormatException` at line 16

9. Transaction fails with unhandled exception

**Expected Result**: All miners can claim fees normally

**Actual Result**: All fee claiming transactions fail with exceptions, cross-chain indexing halts, system operations blocked until round N+1 expires

**Success Condition**: The attack succeeds if any subsequent call to `IsCurrentMiner` throws an unhandled exception, which can be verified by attempting to call `ClaimTransactionFees` or `ProposeCrossChainIndexing` and observing transaction failures.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
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

**File:** protobuf/aedpos_contract.proto (L266-284)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L867-895)
```csharp
    public override Empty ClaimTransactionFees(TotalTransactionFeesMap input)
    {
        AssertSenderIsCurrentMiner();
        var claimTransactionExecuteHeight = State.ClaimTransactionFeeExecuteHeight.Value;

        Assert(claimTransactionExecuteHeight < Context.CurrentHeight,
            $"This method already executed in height {State.ClaimTransactionFeeExecuteHeight.Value}");
        State.ClaimTransactionFeeExecuteHeight.Value = Context.CurrentHeight;
        Context.LogDebug(() => $"Claim transaction fee. {input}");
        State.LatestTotalTransactionFeesMapHash.Value = HashHelper.ComputeFrom(input);
        foreach (var bill in input.Value)
        {
            var symbol = bill.Key;
            var amount = bill.Value;
            ModifyBalance(Context.Self, symbol, amount);
            Context.Fire(new TransactionFeeClaimed
            {
                Symbol = symbol,
                Amount = amount,
                Receiver = Context.Self
            });
            
            TransferTransactionFeesToFeeReceiver(symbol, amount);
        }

        Context.LogDebug(() => "Finish claim transaction fee.");

        return new Empty();
    }
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-291)
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
    }
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
