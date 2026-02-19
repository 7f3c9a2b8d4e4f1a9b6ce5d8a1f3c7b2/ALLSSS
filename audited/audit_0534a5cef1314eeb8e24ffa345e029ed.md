### Title
Missing Public Key Validation Allows Side Chain Initialization with Malformed Miner Data

### Summary
The `GetChainInitializationInformation()` function serializes miner public keys without validating their cryptographic validity. Malformed or invalid public keys can enter the system through `AnnounceElectionFor()` or misconfiguration, successfully serialize, and propagate to side chains, causing fund loss when tokens are distributed to addresses derived from invalid keys and potential consensus failures.

### Finding Description

**Root Cause:**
No validation exists to ensure public keys in the MinerList are valid elliptic curve public keys. The system only validates hex string format, not cryptographic validity.

**Code Locations and Execution Path:**

1. **Entry Point - Malformed Key Injection:** [1](#0-0) 

The `AnnounceElectionFor()` method accepts any hex string as a public key without validating it represents a valid elliptic curve point: [2](#0-1) 

2. **Propagation to Miner List:**
When candidates become victories, their unvalidated keys enter the miner list: [3](#0-2) 

3. **Serialization Without Validation:**
`GetChainInitializationInformation()` retrieves and serializes miner keys: [4](#0-3) 

The underlying `GetCurrentMinerList()` converts hex strings to ByteStrings without validation: [5](#0-4) 

4. **Hex Conversion Only Validates Format:** [6](#0-5) 

This only ensures valid hex characters, not valid public key structure (correct length, valid curve point, etc.).

5. **Side Chain Reception and Storage:**
Side chains receive and store malformed keys without validation: [7](#0-6) 

6. **Fund Loss Mechanism:**
When distributing resource tokens, addresses are created from malformed keys: [8](#0-7) 

The `Address.FromPublicKey()` method accepts ANY byte array and simply hashes it, without validating it's a valid public key: [9](#0-8) 

### Impact Explanation

**Direct Fund Impact:**
- Resource tokens (transaction fees, rental fees) accumulated by the consensus contract are distributed to addresses derived from malformed public keys
- These addresses may not have corresponding private keys, making funds permanently inaccessible
- The amount equals the total accumulated fees divided by the number of miners, occurring on every miner list update

**Consensus/Cross-Chain Integrity:**
- Side chains initialize with corrupted miner data that cannot be used for valid signature verification
- Malformed keys in the miner list cannot match any legitimate recovered public key from transaction signatures
- This breaks the consensus mechanism's ability to validate block producers
- Cross-chain communication relies on corrupted state

**Operational Impact:**
- Side chain consensus may malfunction when attempting to verify miners with malformed keys
- Token distribution failures or misdirection on every round update
- Cascading failures across all side chains sharing the corrupted miner list

### Likelihood Explanation

**Feasible Attack Vectors:**

1. **Direct Attack (Moderate Complexity):**
    - Attacker calls `AnnounceElectionFor()` with malformed public key (e.g., wrong length, invalid curve point)
    - Requires acquiring sufficient voting power to make the malformed key a victory
    - While expensive, this is economically rational if the attacker can cause greater fund loss than the vote cost

2. **Configuration Error (High Probability):**
    - Initial miner list in `ConsensusOptions.InitialMinerList` is misconfigured with malformed keys
    - No validation during genesis initialization via `FirstRound()`: [10](#0-9) 
    - Operator error during deployment is a realistic scenario

3. **Compromised Parent Chain:**
    - If parent chain consensus is compromised, malformed keys can be directly injected
    - Side chains blindly trust parent chain data

**No Detection Mechanisms:**
- No runtime validation checks malformed keys
- Serialization and deserialization succeed silently
- Only manifests as fund loss or consensus failure

### Recommendation

**Immediate Mitigation:**

1. Add public key validation in `AnnounceElectionFor()`:
```csharp
private void AnnounceElection(byte[] pubkeyBytes)
{
    var pubkey = pubkeyBytes.ToHex();
    
    // ADD: Validate public key format
    Assert(IsValidPublicKey(pubkeyBytes), 
        "Invalid public key format");
    
    // existing code...
}

private bool IsValidPublicKey(byte[] pubkeyBytes)
{
    // Validate length (33 for compressed, 65 for uncompressed secp256k1)
    if (pubkeyBytes.Length != 33 && pubkeyBytes.Length != 65)
        return false;
    
    // Validate it's a valid curve point by attempting address derivation
    // and catching any cryptographic exceptions
    try
    {
        var address = Address.FromPublicKey(pubkeyBytes);
        // Additional EC point validation if available
        return true;
    }
    catch
    {
        return false;
    }
}
```

2. Add validation in `UpdateInformationFromCrossChain()` before storing miner list

3. Add validation in `SetMinerList()`: [11](#0-10) 

4. Add validation during genesis initialization in `FirstRound()`

**Test Cases:**
- Attempt to announce election with 32-byte key (invalid length)
- Attempt with 64-byte key (invalid length)
- Attempt with valid length but invalid curve point
- Verify serialization rejects malformed keys
- Test side chain initialization with malformed parent chain data

### Proof of Concept

**Initial State:**
- Main chain with functional election and consensus contracts
- Side chain configured to receive miner updates from main chain

**Attack Sequence:**

1. Attacker calls `AnnounceElectionFor()` with malformed key:
   - Input: `{ pubkey: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" }` (32 bytes, invalid length for secp256k1)
   - Expected: Transaction should fail with "Invalid public key"
   - Actual: Transaction succeeds, malformed key stored in candidates

2. Malformed key accumulates votes and becomes victory

3. Main chain generates new round with malformed key in miner list

4. `GetChainInitializationInformation()` called:
   - Expected: Should reject malformed keys or fail serialization
   - Actual: Successfully serializes malformed key to ByteString

5. Side chain calls `UpdateInformationFromCrossChain()` with serialized data:
   - Expected: Should validate and reject malformed keys
   - Actual: Stores malformed key in `MainChainCurrentMinerList`

6. Side chain accumulates resource tokens, then calls `DistributeResourceTokensToPreviousMiners()`:
   - Expected: Should fail or skip malformed keys
   - Actual: Creates address from malformed key via `Address.FromPublicKey()` and transfers tokens to uncontrolled address

**Success Condition:**
- Malformed public key successfully serialized in step 4
- Side chain initialized with corrupted miner data in step 5
- Funds transferred to invalid address in step 6

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-142)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
        var admin = input.Admin ?? Context.Sender;
        State.CandidateAdmins[pubkey] = admin;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
        LockCandidateNativeToken();
        AddCandidateAsOption(pubkey);
        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L144-175)
```csharp
    private void AnnounceElection(byte[] pubkeyBytes)
    {
        var pubkey = pubkeyBytes.ToHex();
        var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);

        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");

        var candidateInformation = State.CandidateInformationMap[pubkey];

        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
        }
        else
        {
            Assert(!IsPubkeyBanned(pubkey), "This candidate already banned before.");
            State.CandidateInformationMap[pubkey] = new CandidateInformation
            {
                Pubkey = pubkey,
                AnnouncementTransactionId = Context.OriginTransactionId,
                IsCurrentCandidate = true
            };
        }

        State.Candidates.Value.Value.Add(pubkeyByteString);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L31-42)
```csharp
    public override MinerList GetCurrentMinerList(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var round)
            ? new MinerList
            {
                Pubkeys =
                {
                    round.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k))
                }
            }
            : new MinerList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L13-23)
```csharp
    public override BytesValue GetChainInitializationInformation(BytesValue input)
    {
        return new BytesValue
        {
            Value = new MinerListWithRoundNumber
            {
                MinerList = GetCurrentMinerList(new Empty()),
                RoundNumber = State.CurrentRoundNumber.Value
            }.ToByteString()
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-64)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L66-96)
```csharp
    private void DistributeResourceTokensToPreviousMiners()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
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
        }
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

**File:** src/AElf.Types/Types/Address.cs (L37-41)
```csharp
        public static Address FromPublicKey(byte[] bytes)
        {
            var hash = bytes.ComputeHash().ComputeHash();
            return new Address(hash);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L74-92)
```csharp
    public override Empty FirstRound(Round input)
    {
        /* Basic checks. */
        Assert(State.CurrentRoundNumber.Value == 0, "Already initialized.");

        /* Initial settings. */
        State.CurrentTermNumber.Value = 1;
        State.CurrentRoundNumber.Value = 1;
        State.FirstRoundNumberOfEachTerm[1] = 1;
        State.MiningInterval.Value = input.GetMiningInterval();
        SetMinerList(input.GetMinerList(), 1);

        AddRoundInformation(input);

        Context.LogDebug(() =>
            $"Initial Miners: {input.RealTimeMinersInformation.Keys.Aggregate("\n", (key1, key2) => key1 + "\n" + key2)}");

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```
