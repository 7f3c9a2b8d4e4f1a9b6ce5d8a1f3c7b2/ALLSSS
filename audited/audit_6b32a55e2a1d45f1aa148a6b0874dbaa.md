# Audit Report

## Title
Consensus DoS via Malformed Hex Keys in NextRound Input

## Summary
The AEDPoS consensus contract accepts miner public keys as unvalidated strings in `NextRound()` input, allowing a malicious miner to inject non-hex or odd-length keys that get stored in state. Subsequent consensus operations and view methods throw exceptions when attempting to convert these malformed keys to ByteString, causing permanent consensus halt.

## Finding Description

The vulnerability exists because the consensus contract stores round information with string-typed miner public keys but only validates hex format during ByteString conversion, not at input acceptance.

**Attack Flow:**

1. A malicious miner crafts a `NextRoundInput` protobuf message with malformed keys (e.g., "ZZZZ", "invalid", or odd-length "abc") in the `real_time_miners_information` map field. [1](#0-0) 

2. The attacker calls `NextRound()` which accepts this input without validating key format. [2](#0-1) 

3. `ProcessConsensusInformation()` performs `PreCheck()` which only validates the caller is an authorized miner, not the input key format. [3](#0-2) 

4. The consensus validation providers check round numbers, mining order, and time slots but NOT hex format of keys. [4](#0-3) 

5. `ProcessNextRound()` converts input to Round via `ToRound()` which simply copies fields without validation. [5](#0-4) 

6. `AddRoundInformation()` stores the round with malformed keys directly to state. [6](#0-5) 

**DoS Trigger Points:**

Once malformed keys are in state, any operation attempting hex conversion throws exceptions:

1. `GetCurrentMinerList()` view method attempts to convert keys using `ByteStringHelper.FromHexString()`. [7](#0-6) 

2. The hex conversion implementation calls `Convert.ToByte(hex.Substring(i, 2), 16)` which throws `FormatException` for invalid hex characters or `ArgumentOutOfRangeException` for odd-length strings. [8](#0-7) 

3. Subsequent `NextRound()` calls fail in `RecordMinedMinerListOfCurrentRound()` when attempting to convert current round miner keys. [9](#0-8) 

4. `NextTerm()` operations also fail at the same point and when building the new miner list. [10](#0-9) 

## Impact Explanation

**Critical Consensus Halt:**

Once malformed keys are stored, the blockchain enters an unrecoverable state:
- All view methods querying miner lists throw exceptions and fail
- All `NextRound()` transactions attempting to progress consensus throw exceptions  
- All `NextTerm()` transactions attempting term transitions throw exceptions
- Mining reward distribution cannot proceed
- Cross-chain operations depending on miner list synchronization fail
- No automatic recovery mechanism exists

The entire network consensus stops permanently, requiring manual intervention (state rollback or emergency contract upgrade) to recover. This breaks the fundamental availability guarantee of the consensus layer.

## Likelihood Explanation

**Medium-High Probability:**

The attack requires:
- Attacker must be an authorized miner (insider access)
- Single malicious transaction during legitimate mining time slot
- No complex preconditions or multi-step sequences

However:
- Any current miner can execute (realistic insider threat)
- Compromised miner node can automate the attack
- Attack complexity is trivial (craft protobuf with malformed string)
- No detection mechanism exists before state corruption
- Immediate and permanent impact

While requiring miner privileges elevates the trust requirement, the ease of execution and catastrophic impact with no recovery path makes this a realistic and severe threat for any network with potentially compromised or malicious miners.

## Recommendation

Validate hex format of all keys in `real_time_miners_information` before storing round information:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    // Validate all keys are valid hex strings
    foreach (var key in input.RealTimeMinersInformation.Keys)
    {
        Assert(IsValidHexString(key), $"Invalid miner public key format: {key}");
    }
    
    var nextRound = input.ToRound();
    RecordMinedMinerListOfCurrentRound();
    // ... rest of method
}

private bool IsValidHexString(string hex)
{
    if (string.IsNullOrEmpty(hex)) return false;
    
    // Remove optional 0x prefix
    if (hex.Length >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.Substring(2);
    
    // Must have even length
    if (hex.Length % 2 != 0) return false;
    
    // Must contain only hex characters
    foreach (char c in hex)
    {
        if (!((c >= '0' && c <= '9') || 
              (c >= 'a' && c <= 'f') || 
              (c >= 'A' && c <= 'F')))
            return false;
    }
    
    return true;
}
```

Apply the same validation in `ProcessNextTerm()` and any other methods accepting round information with string keys.

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusDoS_MalformedHexKeys_Test()
{
    // Setup: Initialize consensus with valid miners
    var initialMiners = new List<string> { /* valid hex keys */ };
    await InitializeConsensusAsync(initialMiners);
    
    // Attack: Malicious miner submits NextRoundInput with malformed keys
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = 2,
        RealTimeMinersInformation =
        {
            { "ZZZZ", new MinerInRound() },  // Invalid hex characters
            { "abc", new MinerInRound() }     // Odd length
        }
    };
    
    // This succeeds - malformed keys stored in state
    await ConsensusStub.NextRound.SendAsync(maliciousInput);
    
    // DoS triggered - view method throws exception
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await ConsensusStub.GetCurrentMinerList.CallAsync(new Empty());
    });
    
    // Consensus operations also fail
    var consensusException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await ConsensusStub.NextRound.SendAsync(validNextRoundInput);
    });
    
    // Blockchain is now permanently halted
}
```

## Notes

This vulnerability demonstrates a critical gap in input validation where string-typed fields representing cryptographic identifiers are accepted without format validation. The deferred validation during conversion creates a window for state corruption that cannot be recovered from within the protocol. The insider threat model (requiring miner access) is acceptable but the lack of any safeguards against malformed data makes this a severe availability vulnerability.

### Citations

**File:** protobuf/aedpos_contract.proto (L458-462)
```text
message NextRoundInput {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L223-229)
```csharp
    private void RecordMinedMinerListOfCurrentRound()
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        State.MinedMinerListMap.Set(currentRound.RoundNumber, new MinerList
        {
            Pubkeys = { currentRound.GetMinedMiners().Select(m => ByteStringHelper.FromHexString(m.Pubkey)) }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
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
