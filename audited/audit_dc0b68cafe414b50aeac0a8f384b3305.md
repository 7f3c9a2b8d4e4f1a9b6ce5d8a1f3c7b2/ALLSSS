### Title
Unbounded State Growth via Unvalidated EncryptedPieces in Consensus Secret Sharing

### Summary
The `UpdateLatestSecretPieces()` function in the AEDPoS consensus contract accepts an arbitrary number of encrypted pieces from miners without validating that the count matches the expected miner count. A malicious miner can exploit this to cause unbounded state growth by repeatedly submitting oversized `EncryptedPieces` maps, leading to blockchain state bloat and operational DoS.

### Finding Description

The vulnerability exists in two locations where encrypted pieces are added to miner state without validation:

**Location 1**: The `UpdateLatestSecretPieces()` function iterates through all entries in `triggerInformation.EncryptedPieces` and adds them to the round state without any size or count validation. [1](#0-0) 

**Location 2**: The `PerformSecretSharing()` function similarly adds all entries from `input.EncryptedPieces` without validation. [2](#0-1) 

**Root Cause**: The protobuf definition allows arbitrary map sizes for `encrypted_pieces`, and the contract code performs no validation: [3](#0-2) [4](#0-3) 

**Expected vs Actual Behavior**: According to the legitimate secret sharing implementation, each miner should provide exactly `minersCount` encrypted pieces (one per miner, typically 17 based on `SupposedMinersCount`): [5](#0-4) [6](#0-5) 

However, the contract accepts and stores any number of entries without checking against this expected count.

**Execution Path**: 
1. Miner calls consensus methods during block production
2. `GetConsensusExtraData` is invoked with attacker-controlled `triggerInformation`
3. `UpdateLatestSecretPieces` is called when secret sharing is enabled
4. All encrypted pieces are added to state via `updatedRound`
5. Round is persisted to `State.Rounds[roundNumber]` [7](#0-6) [8](#0-7) 

### Impact Explanation

**Operational Impact - State Bloat DoS**:
- A malicious miner can add up to 5MB of encrypted pieces per UpdateValue transaction (transaction size limit)
- With 40,960 rounds kept in state, accumulated bloat can reach 200+ GB if exploited consistently
- All full nodes must store and sync this bloated state
- New nodes face significantly increased sync times
- Storage costs increase proportionally for all node operators
- Eventually makes running a node economically impractical, threatening network decentralization [9](#0-8) [10](#0-9) 

**Severity**: Medium - Does not directly steal funds but causes significant operational degradation and can make the blockchain impractical to operate over time.

### Likelihood Explanation

**Attacker Capabilities**: 
- Requires being in the active miner list (elected through the Election contract)
- Miners are semi-trusted but can become malicious or compromised
- Once elected, miner has full control over their node's consensus data

**Attack Complexity**: 
- Low - Simply modify node software to provide oversized `EncryptedPieces` map
- No complex cryptographic or timing requirements
- Can be automated to execute continuously

**Feasibility Conditions**:
- Secret sharing must be enabled (checked via configuration)
- Attacker must maintain miner status to repeatedly exploit [11](#0-10) 

**Economic Rationality**:
- Transaction size fees apply but are negligible compared to damage inflicted
- No tokens are burned or locked beyond standard transaction fees
- Attacker's election stake remains intact

**Detection**: While state growth would be visible, attributing it to malicious intent vs. legitimate usage may be challenging initially.

**Probability**: Medium - Requires miner status but is trivial to execute once achieved.

### Recommendation

**Immediate Fix**: Add strict validation in both `UpdateLatestSecretPieces()` and `PerformSecretSharing()` to enforce that the number of encrypted pieces matches the expected miner count:

```csharp
private void UpdateLatestSecretPieces(Round updatedRound, string pubkey,
    AElfConsensusTriggerInformation triggerInformation)
{
    var minersCount = updatedRound.RealTimeMinersInformation.Count;
    
    // Validate encrypted pieces count
    Assert(triggerInformation.EncryptedPieces.Count <= minersCount,
        $"Invalid encrypted pieces count: {triggerInformation.EncryptedPieces.Count}, expected max: {minersCount}");
    
    // Validate all keys are valid miner pubkeys
    foreach (var key in triggerInformation.EncryptedPieces.Keys)
        Assert(updatedRound.RealTimeMinersInformation.ContainsKey(key),
            $"Invalid miner pubkey in encrypted pieces: {key}");
    
    foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
        updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
            .Add(encryptedPiece.Key, encryptedPiece.Value);
    
    // ... rest of function
}
```

Similar validation should be added to `PerformSecretSharing()` at line 290.

**Invariant Checks**:
1. `EncryptedPieces.Count <= currentMinersCount` for all miners
2. All keys in `EncryptedPieces` must be valid miner pubkeys from current round
3. Consider adding maximum size limit per piece to prevent large individual entries

**Test Cases**:
1. Test that providing `minersCount + 1` encrypted pieces fails validation
2. Test that providing encrypted pieces with invalid pubkey keys fails validation
3. Test that providing oversized individual pieces fails (if size limit added)
4. Test legitimate secret sharing still works with exact miner count

### Proof of Concept

**Initial State**:
- Blockchain has 17 active miners
- Secret sharing is enabled
- Attacker controls one miner node

**Attack Sequence**:

1. Attacker modifies their miner node to generate malicious `EncryptedPieces` map:
   - Create 1000 fake entries instead of 17 legitimate ones
   - Each entry: random pubkey → random 5KB encrypted data
   - Total: ~5MB per transaction

2. Attacker produces block during their time slot with malicious trigger information

3. `GetConsensusExtraData` processes the malicious data:
   - Calls `UpdateLatestSecretPieces` 
   - Adds all 1000 entries without validation
   - Round state grows by ~5MB

4. Repeat for each round where attacker produces blocks

5. After 100 rounds: 500MB of bloated state
6. After 1000 rounds: 5GB of bloated state
7. Continues accumulating up to 40,960 rounds limit

**Expected Result**: Encrypted pieces count should be validated and transaction should fail

**Actual Result**: All 1000 encrypted pieces are accepted and stored in blockchain state without validation, causing unbounded state growth

**Success Condition**: Node logs show state size increasing by ~5MB per malicious block, and blockchain storage grows proportionally.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L122-125)
```csharp
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L139-141)
```csharp
        foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L290-290)
```csharp
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
```

**File:** protobuf/aedpos_contract.proto (L294-294)
```text
    map<string, bytes> encrypted_pieces = 14;
```

**File:** protobuf/aedpos_contract.proto (L339-339)
```text
    map<string, bytes> encrypted_pieces = 5;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L10-10)
```csharp
    public const int KeepRounds = 40960;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L56-78)
```csharp
    private bool IsSecretSharingEnabled()
    {
        if (State.ConfigurationContract.Value == null)
        {
            var configurationContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
            if (configurationContractAddress == null)
            {
                // Which means Configuration Contract hasn't been deployed yet.
                return false;
            }

            State.ConfigurationContract.Value = configurationContractAddress;
        }

        var secretSharingEnabled = new BoolValue();
        secretSharingEnabled.MergeFrom(State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = AEDPoSContractConstants.SecretSharingEnabledConfigurationKey
        }).Value);

        return secretSharingEnabled.Value;
    }
```
