# Audit Report

## Title
Hex Encoding Case Sensitivity Causes Miner DoS Through Candidate Replacement

## Summary
The consensus contract's `RecordCandidateReplacement` method accepts pubkey strings without case normalization, while all normal operations use lowercase hex from `.ToHex()`. When a candidate admin replaces a miner's pubkey using an uppercase hex string (even for legitimate replacements to different pubkeys), the consensus dictionary stores an uppercase key while all subsequent lookups use lowercase, preventing the miner from producing blocks.

## Finding Description

The vulnerability exists in the interaction between the Election Contract's pubkey replacement flow and the Consensus Contract's miner information storage, specifically in how string-based dictionary keys are handled without case normalization.

**Root Cause - Missing Case Normalization:**

The `RecordCandidateReplacement` method directly uses input strings as dictionary keys without normalization to lowercase. [1](#0-0) 

**Normal Flow Uses Lowercase:**

The `.ToHex()` extension method produces lowercase hexadecimal characters. The encoding formula `b + 0x37 + 0x20` (where `0x37 = 55` and `0x20 = 32`, totaling 87) generates lowercase 'a'-'f' (ASCII 97-102) for byte values 10-15. [2](#0-1) 

All miner dictionary keys are initialized using `.ToHex()`, creating lowercase entries. When generating the first round of a new term, pubkeys are converted to hex and used as dictionary keys. [3](#0-2) 

**Dictionary Access in Block Production:**

When generating consensus extra data, the miner's pubkey bytes are converted to lowercase hex via `ToHex()` and used to access the `RealTimeMinersInformation` dictionary. [4](#0-3) [5](#0-4) 

**Dictionary Access in Consensus Commands:**

The `GetConsensusCommand` method converts the miner's pubkey bytes to lowercase and checks miner list membership. [6](#0-5) [7](#0-6) 

The `IsInMinerList` check performs case-sensitive dictionary lookup using `.Contains()` on the dictionary keys. [8](#0-7) 

**Attack Entry Point:**

The Election Contract's `ReplaceCandidatePubkey` accepts string pubkeys without format validation and passes them directly to the consensus contract. [9](#0-8) [10](#0-9) 

The protobuf message has no format constraints on the string fields. [11](#0-10) [12](#0-11) 

While `HexStringToByteArray` correctly accepts both uppercase and lowercase hex strings for byte conversion [13](#0-12) , the original STRING is used as the dictionary key without normalization.

## Impact Explanation

**Direct Consensus Impact:**
When a miner's pubkey is replaced with an uppercase hex string variant (whether same bytes or different bytes), the consensus dictionary contains an uppercase key while all lookups use lowercase from `ToHex()`. This causes:
- `GetConsensusCommand` returns `InvalidConsensusCommand` because `IsInMinerList` fails the dictionary lookup
- `GetConsensusBlockExtraData` throws `KeyNotFoundException` when attempting to access the miner's information
- The affected miner becomes completely unable to produce blocks

**Consensus Integrity:**
- Affected miners miss their assigned time slots, causing consensus delays
- If multiple miners are affected, block production speed decreases significantly  
- Other miners must compensate, potentially centralizing consensus power
- No automatic recovery mechanism exists beyond performing another replacement with correct case

**Severity Justification:**
HIGH - This is a direct DoS attack on core consensus functionality. Unlike availability issues that degrade performance, this completely prevents specific miners from participating in consensus, violating the fundamental guarantee that elected miners can produce blocks.

## Likelihood Explanation

**Attacker Profile:**
The attacker is a candidate admin - a non-privileged role that candidates set themselves. [14](#0-13)  This role is designed for operational management and requires no special permissions beyond being designated by the candidate.

**Attack Execution:**
1. Candidate admin calls `Election.ReplaceCandidatePubkey`
2. Provides uppercase hex string as `new_pubkey` parameter  
3. Single transaction, no complex timing or state requirements
4. No economic cost beyond transaction fee

**Feasibility:**
- **Preconditions**: Candidate performing legitimate pubkey replacement (common operational scenario)
- **Technical Complexity**: Trivial - simply use uppercase characters in hex string
- **Detection**: Not immediately apparent; only discovered when replacement miner attempts block production
- **Accidental Trigger**: Highly likely if developers/admins use uppercase hex strings, which is common in blockchain tooling and many hex converters

**Likelihood Assessment:**
MEDIUM-HIGH - While requiring candidate admin access, this role is non-privileged and the vulnerability affects ANY legitimate replacement where uppercase hex is used. More concerning, this can occur accidentally when using standard hex representations, making it a realistic operational risk even without malicious intent.

## Recommendation

Add case normalization in `RecordCandidateReplacement` before using the pubkey strings as dictionary keys:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");

    // Normalize to lowercase
    var normalizedOldPubkey = input.OldPubkey.ToLower();
    var normalizedNewPubkey = input.NewPubkey.ToLower();

    if (!TryToGetCurrentRoundInformation(out var currentRound) ||
        !currentRound.RealTimeMinersInformation.ContainsKey(normalizedOldPubkey)) return new Empty();

    var realTimeMinerInformation = currentRound.RealTimeMinersInformation[normalizedOldPubkey];
    realTimeMinerInformation.Pubkey = normalizedNewPubkey;
    currentRound.RealTimeMinersInformation.Remove(normalizedOldPubkey);
    currentRound.RealTimeMinersInformation.Add(normalizedNewPubkey, realTimeMinerInformation);
    if (currentRound.ExtraBlockProducerOfPreviousRound == normalizedOldPubkey)
        currentRound.ExtraBlockProducerOfPreviousRound = normalizedNewPubkey;
    State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

    State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
    {
        OldPubkey = normalizedOldPubkey,
        NewPubkey = normalizedNewPubkey,
        CurrentTermNumber = State.CurrentTermNumber.Value
    });

    return new Empty();
}
```

Alternatively, add validation in `ReplaceCandidatePubkey` to reject non-lowercase hex strings, or normalize them before passing to the consensus contract.

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_UppercaseHex_CausesConsensusDos()
{
    // Setup: Candidate announces election and becomes a miner
    var originalKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = ValidationDataCenterKeyPairs.Last();
    await AnnounceElectionAsync(originalKeyPair, Address.FromPublicKey(candidateAdmin.PublicKey));
    
    // Miner becomes active in current round
    await ProduceBlocksAsync(1);
    
    // Verify miner is in current round (lowercase key)
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var lowercaseKey = originalKeyPair.PublicKey.ToHex();
    currentRound.RealTimeMinersInformation.Keys.ShouldContain(lowercaseKey);
    
    // Replacement with UPPERCASE hex string (same bytes, different case)
    var uppercaseKey = originalKeyPair.PublicKey.ToHex().ToUpper();
    var candidateAdminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, candidateAdmin);
    await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = lowercaseKey,
        NewPubkey = uppercaseKey  // UPPERCASE causes the issue
    });
    
    // Verify consensus dictionary now has UPPERCASE key
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    updatedRound.RealTimeMinersInformation.Keys.ShouldContain(uppercaseKey);
    updatedRound.RealTimeMinersInformation.Keys.ShouldNotContain(lowercaseKey);
    
    // Attempt to get consensus command - fails because ToHex() produces lowercase
    var minerStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ConsensusContractAddress, originalKeyPair);
    var consensusCommand = await minerStub.GetConsensusCommand.CallAsync(
        new BytesValue { Value = originalKeyPair.PublicKey });
    
    // This returns InvalidConsensusCommand due to case mismatch
    consensusCommand.ShouldBe(ConsensusCommandProvider.InvalidConsensusCommand);
    
    // Attempting GetConsensusExtraData would throw KeyNotFoundException
    // (cannot easily test in unit test as it would fail the transaction)
}
```

## Notes

This vulnerability affects legitimate operational flows, not just malicious attacks. The case sensitivity issue can manifest whenever:
1. A candidate performs a legitimate pubkey replacement for key rotation
2. The new pubkey is provided in uppercase (common in many tools)
3. The replacement succeeds but the miner cannot produce blocks afterward

The fix should be implemented in `RecordCandidateReplacement` to ensure consistency with the system's expectation that all pubkey strings are lowercase, matching the output of `ToHex()`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L142-143)
```csharp
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
```

**File:** src/AElf.Types/Extensions/ByteExtensions.cs (L38-41)
```csharp
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = (byte)(bytes[bx] & 0x0F);
                c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L17-37)
```csharp
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();

        var round = new Round();

        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L22-23)
```csharp
        var publicKeyBytes = triggerInformation.Pubkey;
        var pubkey = publicKeyBytes.ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L58-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L19-19)
```csharp
        _processingBlockMinerPubkey = input.Value.ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L26-27)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L186-187)
```csharp
        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** protobuf/election_contract.proto (L504-507)
```text
message ReplaceCandidatePubkeyInput {
    string old_pubkey = 1;
    string new_pubkey = 2;
}
```

**File:** protobuf/aedpos_contract.proto (L452-455)
```text
message RecordCandidateReplacementInput {
    string old_pubkey = 1;
    string new_pubkey = 2;
}
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L19-35)
```csharp
    public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

        // Permission check
        var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
```
