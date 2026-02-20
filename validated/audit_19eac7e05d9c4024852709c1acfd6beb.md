# Audit Report

## Title
Hex Encoding Case Sensitivity Causes Miner DoS Through Candidate Replacement

## Summary
The consensus contract's `RecordCandidateReplacement` method accepts pubkey strings without case normalization, while all normal operations use lowercase hex from `.ToHex()`. A candidate admin can replace a miner's pubkey with an uppercase variant, causing dictionary key mismatches that prevent the miner from producing blocks.

## Finding Description

The vulnerability exists in the interaction between the Election Contract's pubkey replacement flow and the Consensus Contract's miner information storage.

**Root Cause - Missing Case Normalization:**

The `RecordCandidateReplacement` method directly uses input strings as dictionary keys without normalization. It removes the old pubkey entry and adds a new entry using the raw input string. [1](#0-0) 

**Normal Flow Uses Lowercase:**

The `.ToHex()` method produces lowercase hexadecimal characters. The encoding formula `b + 0x37 + 0x20` generates lowercase 'a'-'f' (ASCII 97-102) for hex digits. [2](#0-1) 

**Dictionary Access in Block Production:**

When generating consensus data, the miner's pubkey bytes are converted to lowercase hex via `.ToHex()` and used to access the `RealTimeMinersInformation` dictionary: [3](#0-2) [4](#0-3) 

**Dictionary Access in Consensus Commands:**

The `GetConsensusCommand` method converts pubkey bytes to lowercase and checks miner list membership: [5](#0-4) 

The `IsInMinerList` check performs case-sensitive dictionary lookup using the `Contains` method: [6](#0-5) 

**Attack Entry Point:**

The Election Contract's `ReplaceCandidatePubkey` accepts string pubkeys without format validation and passes them directly to the consensus contract: [7](#0-6) [8](#0-7) 

The protobuf message structure has no format constraints on the pubkey strings: [9](#0-8) 

## Impact Explanation

**Direct Consensus Impact:**
- When a miner's pubkey is replaced with an uppercase variant, the `RealTimeMinersInformation` dictionary contains an uppercase key while all lookups use lowercase
- `GetConsensusCommand` returns `InvalidConsensusCommand` because the `IsInMinerList` check fails with the lowercase lookup against uppercase key
- `GetConsensusBlockExtraData` throws `KeyNotFoundException` when trying to access `currentRound.RealTimeMinersInformation[pubkey]` with a lowercase key that doesn't exist
- The affected miner becomes completely unable to produce blocks

**Consensus Integrity:**
- Affected miners miss their assigned time slots, causing consensus delays
- If multiple miners are affected, block production speed decreases significantly
- Other miners must compensate for missed slots, potentially centralizing consensus power
- No automatic recovery mechanism exists - manual intervention required

**Severity Justification:**
HIGH - This is a direct DoS attack on core consensus functionality. Unlike availability issues that degrade performance, this completely prevents specific miners from participating in consensus, violating the fundamental guarantee that elected miners can produce blocks.

## Likelihood Explanation

**Attacker Profile:**
The attacker is a candidate admin - a non-privileged role that candidates set themselves during election registration. This role is designed for operational management and requires no special permissions beyond being designated by the candidate.

**Attack Execution:**
1. Candidate admin calls `Election.ReplaceCandidatePubkey`
2. Provides uppercase hex string as `new_pubkey` parameter
3. Single transaction, no complex timing or state requirements
4. No economic cost beyond transaction fee

**Feasibility:**
- **Preconditions**: Candidate must be an active miner (common scenario in normal operations)
- **Technical Complexity**: Trivial - just use uppercase characters in hex string
- **Detection**: Not immediately apparent; only discovered when miner attempts block production
- **Accidental Trigger**: Possible if developers/admins use uppercase hex strings (common in blockchain tooling)

**Likelihood Assessment:**
MEDIUM-HIGH - While requiring candidate admin access, this role is non-privileged and the attack is trivially simple. More concerningly, this can occur accidentally when using standard hex representations, making it a realistic operational risk even without malicious intent.

## Recommendation

Add case normalization to the `RecordCandidateReplacement` method before using the pubkey strings as dictionary keys:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");

    // Normalize to lowercase to match ToHex() output
    var oldPubkey = input.OldPubkey.ToLower();
    var newPubkey = input.NewPubkey.ToLower();

    if (!TryToGetCurrentRoundInformation(out var currentRound) ||
        !currentRound.RealTimeMinersInformation.ContainsKey(oldPubkey)) return new Empty();

    var realTimeMinerInformation = currentRound.RealTimeMinersInformation[oldPubkey];
    realTimeMinerInformation.Pubkey = newPubkey;
    currentRound.RealTimeMinersInformation.Remove(oldPubkey);
    currentRound.RealTimeMinersInformation.Add(newPubkey, realTimeMinerInformation);
    if (currentRound.ExtraBlockProducerOfPreviousRound == oldPubkey)
        currentRound.ExtraBlockProducerOfPreviousRound = newPubkey;
    State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

    // ... rest of the method
}
```

Additionally, add validation in the Election contract to enforce lowercase format:

```csharp
public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
{
    // Normalize inputs to lowercase
    var oldPubkey = input.OldPubkey.ToLower();
    var newPubkey = input.NewPubkey.ToLower();
    
    Assert(IsCurrentCandidateOrInitialMiner(oldPubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(oldPubkey) && !IsPubkeyBanned(newPubkey),
        "Pubkey is in already banned.");
    
    // ... continue with normalized pubkeys
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_UppercaseHex_CausesMinerDoS()
{
    // Setup: Create a candidate who becomes a miner
    var minerKeyPair = ValidationDataCenterKeyPairs.First();
    var candidateAdmin = ValidationDataCenterKeyPairs.Last();
    var candidateAdminAddress = Address.FromPublicKey(candidateAdmin.PublicKey);
    
    // Candidate announces election with admin
    await AnnounceElectionAsync(minerKeyPair, candidateAdminAddress);
    
    // Candidate becomes active miner through voting/election process
    // ... (voting and term transition logic)
    
    // Get current round information - miner is in the list with lowercase key
    var roundBefore = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var lowercaseKey = minerKeyPair.PublicKey.ToHex(); // lowercase from ToHex()
    roundBefore.RealTimeMinersInformation.ContainsKey(lowercaseKey).ShouldBeTrue();
    
    // Attack: Admin replaces pubkey with UPPERCASE variant
    var candidateAdminStub = GetElectionContractTester(candidateAdmin);
    var uppercaseKey = minerKeyPair.PublicKey.ToHex().ToUpper(); // UPPERCASE hex
    await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = lowercaseKey,
        NewPubkey = uppercaseKey  // Uppercase causes the vulnerability
    });
    
    // Verify: Dictionary now has uppercase key
    var roundAfter = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    roundAfter.RealTimeMinersInformation.ContainsKey(uppercaseKey).ShouldBeTrue();
    roundAfter.RealTimeMinersInformation.ContainsKey(lowercaseKey).ShouldBeFalse();
    
    // Impact: Miner cannot get consensus command (uses lowercase lookup)
    var minerStub = GetAEDPoSContractTester(minerKeyPair);
    var command = await minerStub.GetConsensusCommand.CallAsync(
        ByteString.CopyFrom(minerKeyPair.PublicKey));
    
    // Miner gets InvalidConsensusCommand because IsInMinerList fails
    command.ShouldBe(ConsensusCommandProvider.InvalidConsensusCommand);
    
    // Attempting to produce block will throw KeyNotFoundException
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(minerKeyPair.PublicKey),
        Behaviour = AElfConsensusBehaviour.UpdateValue
    };
    
    var exception = await Assert.ThrowsAsync<KeyNotFoundException>(async () =>
    {
        await minerStub.GetConsensusExtraData.CallAsync(triggerInfo.ToBytesValue());
    });
    
    // Miner is now completely unable to produce blocks
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
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
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```

**File:** src/AElf.Types/Extensions/ByteExtensions.cs (L21-45)
```csharp
        public static string ToHex(this byte[] bytes, bool withPrefix = false)
        {
            var offset = withPrefix ? 2 : 0;
            var length = bytes.Length * 2 + offset;
            var c = new char[length];

            byte b;

            if (withPrefix)
            {
                c[0] = '0';
                c[1] = 'x';
            }

            for (int bx = 0, cx = offset; bx < bytes.Length; ++bx, ++cx)
            {
                b = (byte)(bytes[bx] >> 4);
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = (byte)(bytes[bx] & 0x0F);
                c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
            }

            return new string(c);
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-27)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
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
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** protobuf/aedpos_contract.proto (L452-455)
```text
message RecordCandidateReplacementInput {
    string old_pubkey = 1;
    string new_pubkey = 2;
}
```
