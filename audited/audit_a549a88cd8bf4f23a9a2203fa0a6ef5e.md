### Title
Missing Validation for Empty Public Keys in Miner List Causes Consensus DoS

### Summary
The `MinerList.GenerateFirstRoundOfNewTerm` method accesses the first byte of each miner's public key without validating that the ByteString is non-empty. When an empty public key is present in the miner list, accessing `miner[0]` throws an `IndexOutOfRangeException`, causing consensus failure and preventing term transitions. This vulnerability can be exploited through malicious genesis configuration or candidate replacement mechanisms.

### Finding Description

The root cause is in `MinerList.GenerateFirstRoundOfNewTerm` where public keys are sorted by their first byte without validation: [1](#0-0) 

The code creates a dictionary using `miner.ToHex()` as key and `miner[0]` as value. If any ByteString in `Pubkeys` is empty (0 bytes), accessing `miner[0]` throws `IndexOutOfRangeException`.

**Attack Vector 1: Genesis Configuration**

The initialization flow converts hex strings to ByteStrings without validating length: [2](#0-1) 

The configuration validation only checks the first element: [3](#0-2) 

Empty strings at positions [1], [2], etc. bypass validation. When `ByteStringHelper.FromHexString("")` is called, it produces an empty ByteString: [4](#0-3) 

For empty strings, `numberChars = 0` and `bytes = new byte[0]` (empty array).

**Attack Vector 2: Candidate Replacement**

The `RecordCandidateReplacement` method adds new public keys to `RealTimeMinersInformation` without validation: [5](#0-4) 

Similarly, the Election contract's `ReplaceCandidatePubkey` does not validate the new public key length: [6](#0-5) 

**Propagation Through Term Transitions**

During term transitions, the fallback path uses existing miners from the current round: [7](#0-6) 

Empty keys in `RealTimeMinersInformation` persist through this mechanism, continuously triggering the exception.

### Impact Explanation

**Consensus Failure (DoS):** When `GenerateFirstRoundOfNewTerm` is called with an empty public key, the `IndexOutOfRangeException` at line 17 prevents round generation. This causes:
- Chain initialization failure if exploited during genesis
- Permanent inability to transition to new terms if exploited during operation
- Complete consensus breakdown requiring emergency intervention

**Affected Parties:** All network participants - validators cannot produce blocks, users cannot submit transactions, and the entire chain halts.

**Severity: HIGH** - Complete operational failure of consensus mechanism with no automatic recovery path.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. **Genesis Configuration Control**: Requires ability to set initial configuration before chain deployment
2. **Election Contract Authority**: Requires ability to call `ReplaceCandidatePubkey` through proper authorization (candidate admin role)

**Attack Complexity: LOW** - Simple configuration change or authorized contract call with empty string parameter.

**Feasibility Conditions:**
- For genesis attack: Access to chain configuration during deployment
- For runtime attack: Legitimate candidate admin calling replacement with malicious input

**Detection Constraints:** No runtime validation catches empty public keys before they trigger the exception.

**Probability: MEDIUM** - While genesis configuration is typically controlled, the lack of input validation creates risk. Insider threats or compromised admin accounts make runtime exploitation feasible.

### Recommendation

**1. Add Public Key Length Validation in MinerList:**
```
Add validation before line 17 in MinerList.cs:
Assert all ByteStrings in Pubkeys have Length > 0
```

**2. Validate in RecordCandidateReplacement:** [8](#0-7) 

Add assertion after line 133:
```
Assert(!string.IsNullOrWhiteSpace(input.NewPubkey) && input.NewPubkey.Length >= minimum_pubkey_length, "Invalid new pubkey");
```

**3. Validate in ReplaceCandidatePubkey:** [6](#0-5) 

Add validation after line 178:
```
Assert(!string.IsNullOrWhiteSpace(input.NewPubkey) && input.NewPubkey.Length >= minimum_pubkey_length, "Invalid new pubkey");
```

**4. Strengthen Configuration Validation:** [3](#0-2) 

Change to validate all elements:
```
Assert option.InitialMinerList.All(pk => !string.IsNullOrWhiteSpace(pk) && pk.Length >= minimum_length)
```

**5. Add Test Cases:**
- Test `GenerateFirstRoundOfNewTerm` with empty ByteString in Pubkeys
- Test `RecordCandidateReplacement` with empty NewPubkey
- Test genesis initialization with empty string in InitialMinerList beyond position 0

### Proof of Concept

**Initial State:** Deploy chain with malicious genesis configuration

**Attack Steps:**
1. Configure `InitialMinerList` in genesis:
   ```json
   "InitialMinerList": ["valid_public_key_hex_64_chars", ""]
   ```

2. Chain initialization flow executes:
   - `AEDPoSContractInitializationProvider` calls `ByteStringHelper.FromHexString("")` → produces empty ByteString
   - `MinerList.GenerateFirstRoundOfNewTerm` is invoked
   - Line 17 attempts `miner[0]` on empty ByteString

**Expected Result:** Round generation completes successfully

**Actual Result:** `IndexOutOfRangeException` thrown at line 17, chain initialization fails

**Success Condition:** Chain cannot initialize or transition terms, consensus permanently broken

### Notes

The vulnerability described in the audit question suggested "lookup failures" but the actual issue is an uncaught exception that crashes round generation. The impact is more severe than simple lookup failures - it's a complete DoS of the consensus mechanism. The vulnerability is exploitable through multiple paths (genesis, candidate replacement) and has no automatic recovery mechanism once triggered.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/AEDPoSContractInitializationProvider.cs (L43-50)
```csharp
                Params = new MinerList
                {
                    Pubkeys =
                    {
                        initializationData.InitialMinerList.Select(ByteStringHelper.FromHexString)
                    }
                }.GenerateFirstRoundOfNewTerm(initializationData.MiningInterval,
                    initializationData.StartTimestamp.ToDateTime()).ToByteString()
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/AEDPoSAElfModule.cs (L60-68)
```csharp
            if (option.InitialMinerList == null || option.InitialMinerList.Count == 0 ||
                string.IsNullOrWhiteSpace(option.InitialMinerList[0]))
                // If InitialMinerList isn't configured yet, then read AccountService and config current user as single initial miner.
                AsyncHelper.RunSync(async () =>
                {
                    var accountService = context.Services.GetRequiredServiceLazy<IAccountService>().Value;
                    var publicKey = (await accountService.GetPublicKeyAsync()).ToHex();
                    option.InitialMinerList = new List<string> { publicKey };
                });
```

**File:** src/AElf.Types/Helper/ByteArrayHelper.cs (L8-18)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-143)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-187)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);

        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L236-241)
```csharp
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
```
