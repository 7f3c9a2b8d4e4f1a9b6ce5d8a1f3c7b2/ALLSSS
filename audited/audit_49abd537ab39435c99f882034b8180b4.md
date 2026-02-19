### Title
Missing Secp256k1 Public Key Validation in Cross-Chain Miner List Update Enables Token Loss and Consensus Disruption

### Summary
The `UpdateInformationFromCrossChain()` function extracts miner public keys from cross-chain consensus data and stores them in `MainChainCurrentMinerList` without validating that they are valid secp256k1 public keys. This allows invalid or malformed keys to be committed to state, which subsequently causes resource tokens to be sent to arbitrary/invalid addresses during distribution, and can trigger exceptions during consensus round generation, disrupting side chain operation.

### Finding Description

The vulnerability exists in the cross-chain consensus information update flow for side chains:

**Root Cause Location:** [1](#0-0) 

At this location, the function extracts miner public keys from the main chain's `RealTimeMinersInformation` dictionary keys (which are hex strings) and converts them to `ByteString` objects using `ByteStringHelper.FromHexString()`, then stores them directly in `State.MainChainCurrentMinerList` without any validation that these represent valid secp256k1 public keys.

**Why Validation is Critical:**
The secp256k1 public key format has specific requirements (65 bytes uncompressed: 0x04 prefix + 32-byte x-coordinate + 32-byte y-coordinate, or 33 bytes compressed). Invalid data can be:
- Empty ByteStrings
- Arbitrary byte sequences that don't represent valid elliptic curve points
- Truncated or corrupted key data

**Impact Point 1 - Token Distribution:** [2](#0-1) 

The `DistributeResourceTokensToPreviousMiners()` function iterates through the stored public keys and calls `Address.FromPublicKey()` to derive addresses for token distribution. The critical issue is that `Address.FromPublicKey()` performs no validation: [3](#0-2) 

This method simply double-hashes ANY input bytes, producing an address even for invalid public keys. Consequently, resource tokens (ELF and other fee symbols accumulated by the consensus contract) are transferred to addresses derived from invalid keys, effectively locking those funds permanently.

**Impact Point 2 - Consensus Round Generation:** [4](#0-3) 

When the side chain detects the main chain miner list has changed, it calls `GenerateFirstRoundOfNewTerm()` on the stored `MainChainCurrentMinerList`: [5](#0-4) 

This code attempts to access `miner[0]` (the first byte) of each public key ByteString for sorting purposes. If any ByteString is empty or has insufficient length, this will throw an `IndexOutOfRangeException` or similar error, causing the consensus round generation to fail and disrupting the entire side chain's block production.

**Attack Entry Point:** [6](#0-5) 

The malformed data enters through the cross-chain indexing mechanism, where parent chain block `ExtraData` containing consensus information is extracted and passed directly to the consensus contract without validation.

**Available Validation Method (Not Used):** [7](#0-6) 

The codebase provides `PublicKeyParse()` through the Secp256k1Net library which validates whether bytes represent a valid secp256k1 public key, but this validation is never applied in the update flow.

### Impact Explanation

**Direct Financial Impact:**
Resource tokens (transaction fees and rental fees) accumulated by the consensus contract are permanently lost when distributed to addresses derived from invalid public keys. The amount depends on accumulated fees between distribution cycles, potentially representing significant value on an active side chain.

**Consensus Disruption Impact:**
If empty or malformed keys are stored, the next attempt to generate a new consensus round when the miner list changes will fail with an exception, halting block production on the side chain. This represents a critical operational failure requiring manual intervention.

**Affected Parties:**
- Side chain miners: Lose expected resource token distributions
- Side chain users: Experience service disruption if consensus fails
- Cross-chain operations: Blocked during consensus failure

**Severity Justification:**
HIGH severity due to:
1. Permanent loss of accumulated fee tokens
2. Potential complete side chain consensus failure
3. No recovery mechanism for locked tokens
4. State corruption persists until manually corrected

### Likelihood Explanation

**Attack Vector Analysis:**
The function is only callable by the CrossChain contract (authorization check at lines 34-36), not directly by external attackers. However, exploitation can occur through:

1. **Malformed Main Chain Data**: If the main chain produces blocks with invalid consensus data (due to bugs in block production or serialization)
2. **Serialization/Deserialization Bugs**: Errors in protobuf parsing or hex string conversion could corrupt public key data
3. **Cross-Chain Data Corruption**: Network issues or bugs in cross-chain indexing could introduce malformed data

**Feasibility Assessment:**
- No direct attacker control required - can occur through system bugs
- Cross-chain indexing is governance-controlled but doesn't validate content
- Single occurrence of malformed data causes persistent state corruption
- Real-world blockchain systems have experienced serialization bugs

**Probability Factors:**
- MEDIUM-LOW direct exploitation by attackers (requires main chain compromise)
- MEDIUM probability of triggering through bugs in complex cross-chain data flow
- HIGH impact when triggered justifies classification as HIGH severity despite moderate probability

**Detection and Prevention:**
Currently no validation exists to detect or prevent invalid keys from being stored, making the system vulnerable to both malicious and accidental data corruption.

### Recommendation

**Immediate Fix:**
Add secp256k1 public key validation in `UpdateInformationFromCrossChain()` before storing keys to `MainChainCurrentMinerList`:

```csharp
// After line 57, before line 58-61
var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;

// Validate each public key
var validatedPubkeys = new List<ByteString>();
foreach (var key in minersKeys)
{
    var pubkeyBytes = ByteStringHelper.FromHexString(key);
    
    // Validate it's a proper secp256k1 public key
    // Expected length: 65 bytes (uncompressed) or 33 bytes (compressed)
    if (pubkeyBytes.Length != 65 && pubkeyBytes.Length != 33)
    {
        Context.LogDebug(() => $"Invalid public key length: {pubkeyBytes.Length} for key {key}");
        continue; // Skip invalid key
    }
    
    // Validate it's a valid curve point using Secp256k1
    try
    {
        var secp256k1 = new Secp256k1();
        var parsed = new byte[64]; // Internal format
        if (!secp256k1.PublicKeyParse(parsed, pubkeyBytes.ToByteArray()))
        {
            Context.LogDebug(() => $"Failed to parse public key: {key}");
            continue; // Skip invalid key
        }
        validatedPubkeys.Add(pubkeyBytes);
    }
    catch
    {
        Context.LogDebug(() => $"Exception validating public key: {key}");
        continue; // Skip invalid key
    }
}

// Only update if we have valid keys
Assert(validatedPubkeys.Count > 0, "No valid public keys in cross-chain consensus information");

State.MainChainCurrentMinerList.Value = new MinerList
{
    Pubkeys = { validatedPubkeys }
};
```

**Additional Safeguards:**
1. Add length validation before accessing `miner[0]` in `GenerateFirstRoundOfNewTerm()`
2. Implement defensive checks in `DistributeResourceTokensToPreviousMiners()` to verify address derivation success
3. Add unit tests with malformed public key scenarios
4. Consider adding a view function to validate stored miner list integrity

**Test Cases:**
- Empty ByteString in miner list
- Truncated public key (< 33 bytes)
- Oversized public key (> 65 bytes)
- Valid length but invalid curve point
- All-zero bytes public key
- Mixed valid and invalid keys in same update

### Proof of Concept

**Required Initial State:**
- Side chain initialized with AEDPoS consensus
- CrossChain contract deployed and linked
- Some resource tokens accumulated in consensus contract (e.g., 1000 READ tokens)

**Attack Sequence:**

1. **Setup Malformed Consensus Data:**
```csharp
var malformedHeaderInformation = new AElfConsensusHeaderInformation
{
    Round = new Round
    {
        RoundNumber = 2,
        RealTimeMinersInformation =
        {
            // Valid key
            { validMinerKey1, new MinerInRound() },
            // Invalid: empty key (hex string of empty bytes)
            { "00", new MinerInRound() },
            // Invalid: truncated key
            { "04aaaa", new MinerInRound() }
        }
    }
};
```

2. **Trigger Cross-Chain Update (simulating CrossChain contract):**
```csharp
await crossChainContractStub.UpdateInformationFromCrossChain.SendAsync(
    new BytesValue { Value = malformedHeaderInformation.ToByteString() }
);
```

3. **Verify Invalid Keys Stored:**
```csharp
var minerList = await consensusStub.GetMainChainCurrentMinerList.CallAsync(new Empty());
// minerList.Pubkeys will contain invalid keys without validation
```

4. **Trigger Token Distribution:**
```csharp
// Next cross-chain update triggers DistributeResourceTokensToPreviousMiners()
await crossChainContractStub.UpdateInformationFromCrossChain.SendAsync(
    new BytesValue { Value = nextRoundInformation.ToByteString() }
);
```

**Expected Result (Current Vulnerable Code):**
- Invalid keys successfully stored in `MainChainCurrentMinerList`
- Token distribution sends funds to arbitrary addresses derived from invalid keys
- Tokens permanently locked at invalid addresses
- If consensus attempts round generation with empty key, throws exception and halts

**Expected Result (After Fix):**
- Invalid keys rejected during validation
- Only valid keys stored in `MainChainCurrentMinerList`
- Token distribution only to legitimate miner addresses
- Consensus round generation succeeds with validated keys

**Success Condition:**
The vulnerability is confirmed if tokens are transferred to addresses that cannot be derived from any legitimate secp256k1 key pair, and/or if consensus round generation fails with an exception when processing malformed keys.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L57-61)
```csharp
        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L84-94)
```csharp
            foreach (var pubkey in minerList)
            {
                var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
                Context.LogDebug(() => $"Will send {amount} {symbol}s to {pubkey}");
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
```

**File:** src/AElf.Types/Types/Address.cs (L37-41)
```csharp
        public static Address FromPublicKey(byte[] bytes)
        {
            var hash = bytes.ComputeHash().ComputeHash();
            return new Address(hash);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-294)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L783-788)
```csharp
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
            }
```

**File:** src/AElf.Cryptography/Core/Secp256k1Curve.cs (L89-98)
```csharp
        public IECPoint DeserializePoint(byte[] input)
        {
            var pkBytes = new byte[Secp256k1.PUBKEY_LENGTH];
            if (!_inner.PublicKeyParse(pkBytes, input))
            {
                throw new InvalidSerializedPublicKeyException();
            }

            return Secp256k1Point.FromNative(pkBytes);
        }
```
