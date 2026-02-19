# Audit Report

## Title
Hex Case Mismatch in Pubkey Replacement Causes Miner Denial of Service

## Summary
The `RecordCandidateReplacement` method accepts pubkey strings without normalizing hex case before storing them as dictionary keys in `RealTimeMinersInformation`. When a replaced miner attempts to get consensus commands, the system converts their pubkey to lowercase hex, causing a key mismatch if the replacement was stored with uppercase or mixed case. This prevents the affected miner from producing blocks.

## Finding Description

The vulnerability exists in the pubkey replacement flow where case-sensitive string comparison causes miner lookup failures.

**Root Cause**: The `RecordCandidateReplacement` method directly uses `input.NewPubkey` as a dictionary key without normalizing the hex string format. [1](#0-0) 

**Entry Point**: Candidate admins call `ReplaceCandidatePubkey` with user-provided strings that flow unchanged into the consensus contract. [2](#0-1) 

**Failure Point**: When miners request consensus commands, the system converts input bytes to lowercase hex using `ToHex()`, then performs a case-sensitive dictionary lookup via `IsInMinerList()`. [3](#0-2) [4](#0-3) 

**Hex Conversion Behavior**: The `ToHex()` method produces lowercase hex characters by adding 0x20 (32) to the base value, converting 'A'-'F' to 'a'-'f'. [5](#0-4) 

**Initial Miner List**: All initial pubkeys are normalized to lowercase via `ToHex()`, establishing the expected format. [6](#0-5) 

**Lack of Validation**: The validation only checks hex string convertibility, not case. `ByteArrayHelper.HexStringToByteArray()` is case-insensitive, accepting both uppercase and lowercase. [7](#0-6) 

## Impact Explanation

**Direct Harm:**
- The affected miner cannot retrieve valid consensus commands, preventing block production
- Network consensus capacity is reduced by one miner per affected replacement
- The miner loses potential block rewards during the outage period
- If multiple miners are affected, network liveness could be severely impacted

**Affected Parties:**
- The miner whose pubkey was replaced with incorrect hex case cannot participate in consensus
- The blockchain network suffers from reduced consensus participation and potentially slower block times
- Users may experience degraded network performance if multiple miners are affected simultaneously

**Severity Assessment (Medium):**
- No direct fund theft or permanent loss occurs
- Causes operational disruption to the consensus mechanism
- Can be remediated by calling `ReplaceCandidatePubkey` again with correct (lowercase) format
- Requires privileged admin action to trigger, reducing likelihood
- Impact severity scales with the number of affected miners

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a candidate admin authorized to call `ReplaceCandidatePubkey`
- Must provide new pubkey in non-lowercase format (uppercase or mixed case)
- No special technical knowledge beyond basic hex string manipulation

**Attack Complexity:**
- Low complexity: Single transaction with uppercase hex string
- No timing requirements or race conditions needed
- Deterministic outcome - always causes miner DoS when case mismatches

**Feasibility Conditions:**
- All test cases use `.ToHex()` producing lowercase, but this is convention not enforcement [8](#0-7) 

- Nothing in the contract level enforces lowercase format
- Manual API calls or custom UI inputs could provide uppercase strings
- The validation accepts any valid hex string regardless of case

**Probability Assessment:**
- Moderate probability: Requires deviation from standard patterns but no validation prevents it
- More likely to be accidental (admin copy-paste error) than malicious
- Detection would occur immediately when miner fails to produce blocks
- Recovery requires another admin transaction to fix the replacement

## Recommendation

Normalize all pubkey strings to lowercase before storing them in `RealTimeMinersInformation`. Add this normalization in the `RecordCandidateReplacement` method:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");

    // Normalize pubkeys to lowercase for consistent dictionary key comparison
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

    // Update notification to use normalized pubkey
    State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
    {
        OldPubkey = oldPubkey,
        NewPubkey = newPubkey,
        CurrentTermNumber = State.CurrentTermNumber.Value
    });

    return new Empty();
}
```

Additionally, consider adding validation in `ReplaceCandidatePubkey` to reject non-lowercase hex strings or automatically normalize them before passing to the consensus contract.

## Proof of Concept

```csharp
[Fact]
public async Task ReplaceCandidatePubkey_UppercaseHex_CausesMinerDos()
{
    // Setup: Announce election and become a miner
    var candidateKeyPair = ValidationDataCenterKeyPairs.First();
    var adminKeyPair = ValidationDataCenterKeyPairs.Last();
    var adminAddress = Address.FromPublicKey(adminKeyPair.PublicKey);
    
    await AnnounceElectionAsync(candidateKeyPair, adminAddress);
    await VoteToCandidate(candidateKeyPair.PublicKey, 100_000);
    await NextTerm(InitialCoreDataCenterKeyPairs[0]);
    
    // Verify miner can get consensus commands with lowercase pubkey (normal flow)
    var consensusStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ConsensusContractAddress, candidateKeyPair);
    var commandBefore = await consensusStub.GetConsensusCommand.CallAsync(
        ByteString.CopyFrom(candidateKeyPair.PublicKey));
    commandBefore.ShouldNotBe(ConsensusCommand.InvalidConsensusCommand);
    
    // Exploit: Admin replaces with UPPERCASE hex string
    var newKeyPair = ValidationDataCenterKeyPairs.Skip(1).First();
    var adminStub = GetTester<ElectionContractImplContainer.ElectionContractImplStub>(
        ElectionContractAddress, adminKeyPair);
    await adminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = candidateKeyPair.PublicKey.ToHex(),
        NewPubkey = newKeyPair.PublicKey.ToHex().ToUpper() // UPPERCASE HEX
    });
    
    // Verify: Miner cannot get consensus commands due to case mismatch
    var newConsensusStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ConsensusContractAddress, newKeyPair);
    var commandAfter = await newConsensusStub.GetConsensusCommand.CallAsync(
        ByteString.CopyFrom(newKeyPair.PublicKey));
    
    // Miner is DoS'd - cannot produce blocks
    commandAfter.ShouldBe(ConsensusCommand.InvalidConsensusCommand);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L174-257)
```csharp
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

        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }

        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }

        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }

        //     For CandidateVotes and CandidateInformation, just replace value of origin pubkey.
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }

        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }

        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;

        ReplaceCandidateProfitsReceiver(input.OldPubkey, input.NewPubkey);
        
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });

        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L129-135)
```csharp
    public MinerList GetMinerList()
    {
        return new MinerList
        {
            Pubkeys = { RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
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

**File:** test/AElf.Contracts.Election.Tests/BVT/ReplaceCandidateTests.cs (L38-42)
```csharp
        await candidateAdminStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
        {
            OldPubkey = announceElectionKeyPair.PublicKey.ToHex(),
            NewPubkey = newKeyPair.PublicKey.ToHex()
        });
```
