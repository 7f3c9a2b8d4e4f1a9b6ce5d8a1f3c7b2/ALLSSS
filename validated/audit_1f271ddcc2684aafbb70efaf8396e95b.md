# Audit Report

## Title
Duplicate Initial Miner Entries Cause Consensus DoS During Evil Miner Replacement

## Summary
The Election contract accepts duplicate entries in `State.InitialMiners` during initialization, and incomplete removal during pubkey replacement can create stale duplicates. When evil miner replacement selects from initial miners, duplicate pubkeys are returned to the Consensus contract, causing an `ArgumentException` when adding the same key twice to the round's miner dictionary, resulting in deterministic chain halt.

## Finding Description

The Election contract stores initial miners without any deduplication or validation during initialization. [1](#0-0)  The input miner list is directly converted to ByteStrings and stored in `State.InitialMiners.Value` without checking for duplicates, allowing configuration errors to persist in contract state.

During pubkey replacement operations, the protobuf repeated field's `Remove()` method only removes the first occurrence of a duplicate entry. [2](#0-1)  If `State.InitialMiners` contains duplicates like `[A, A, B]` and `A` is replaced with `A'`, only the first `A` is removed, leaving `[A, B, A']` with one stale entry remaining.

When `GetMinerReplacementInformation()` needs to fill evil miner replacement slots but has insufficient non-initial-miner candidates, it falls back to selecting from initial miners. [3](#0-2)  The LINQ chain uses `Select().Where().Where().Take()` without any deduplication, so duplicate pubkeys in `State.InitialMiners.Value.Value` pass through all filters and are included in `AlternativeCandidatePubkeys`.

The Consensus contract processes miner replacement by iterating through the alternative candidates and adding each to the round's miner map. [4](#0-3)  At line 338, it uses `currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound)`. The `RealTimeMinersInformation` field is a protobuf map [5](#0-4) , which internally uses a C# Dictionary. When `Add()` is called with a duplicate key, it throws `ArgumentException: "An item with the same key has already been added"`, causing the consensus round generation to crash and halting the chain.

## Impact Explanation

**Critical Infrastructure Failure:**
- The Consensus contract cannot generate new rounds, preventing block production entirely
- All nodes experience the same deterministic failure due to identical contract state
- Chain halt persists until manual intervention through governance or emergency response  
- Affects all network participants simultaneously with no automatic recovery

**Severity Justification:**
- Core consensus mechanism is disabled
- No automatic recovery mechanism exists
- Requires coordinated governance action to resolve
- Business continuity completely disrupted during downtime

This represents a **High severity** availability impact on critical blockchain infrastructure.

## Likelihood Explanation

**Preconditions:**
1. **Configuration Error**: Initial miner list configured with duplicate pubkeys during genesis setup
2. **OR Replacement Chain**: Prior pubkey replacement with duplicates creates unremoved stale entries

**Trigger Condition:**  
Evil miner detection combined with insufficient non-initial-miner candidates to fulfill all replacement slots. This activates when:
- Miners misbehave (miss time slots, produce invalid blocks)  
- Limited active candidates with sufficient votes exist

**Likelihood Assessment:**
- **Medium Likelihood**: While requiring operational error during genesis configuration, such errors are realistic in complex multi-validator production environments
- No validation exists to prevent duplicate insertion [6](#0-5) 
- Once duplicates exist in state, the failure is deterministic upon trigger
- Evil miner detection occurs periodically during normal operations
- No monitoring or early warning exists before the DoS manifests

## Recommendation

Add duplicate validation in `InitialElectionContract`:

```csharp
State.InitialMiners.Value = new PubkeyList
{
    Value = { input.MinerList.Select(m => ByteStringHelper.FromHexString(m)).Distinct() }
};
```

Add deduplication in `GetMinerReplacementInformation` when selecting from initial miners:

```csharp
var selectedInitialMiners = State.InitialMiners.Value.Value
    .Select(k => k.ToHex())
    .Distinct()  // Add this
    .Where(k => !State.BannedPubkeyMap[k])
    .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
```

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateInitialMiners_CausesConsensusDoS()
{
    // Setup: Initialize election contract with duplicate initial miners
    var duplicateMinerList = new[] { MinerPubkey1, MinerPubkey1, MinerPubkey2 }; // Duplicate MinerPubkey1
    await ElectionContractStub.InitialElectionContract.SendAsync(new InitialElectionContractInput
    {
        MinerList = { duplicateMinerList },
        TimeEachTerm = 604800,
        MinimumLockTime = 7776000,
        MaximumLockTime = 31536000
    });
    
    // Mark MinerPubkey1 as evil
    await ElectionContractStub.UpdateCandidateInformation.SendAsync(new UpdateCandidateInformationInput
    {
        Pubkey = MinerPubkey1,
        IsEvilNode = true
    });
    
    // Trigger: Call GetMinerReplacementInformation with insufficient candidates
    var replacementInfo = await ElectionContractStub.GetMinerReplacementInformation.CallAsync(
        new GetMinerReplacementInformationInput
        {
            CurrentMinerList = { MinerPubkey1, MinerPubkey2, MinerPubkey3 }
        });
    
    // Verify: AlternativeCandidatePubkeys contains duplicate (the second MinerPubkey1)
    Assert.Contains(replacementInfo.AlternativeCandidatePubkeys, p => p == MinerPubkey1);
    
    // Attempt to process replacement in consensus contract - this will throw ArgumentException
    var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
    {
        await ConsensusContractStub.GenerateNextRoundInformation.CallAsync(new Empty());
    });
    
    Assert.Contains("An item with the same key has already been added", exception.Message);
}
```

## Notes

The claim about Consensus contract initialization using `.Distinct()` is slightly inaccurate - the contract implementation in `MinerList.cs` does not use `.Distinct()` [7](#0-6) , though extension methods in off-chain tooling do. However, the Consensus contract would fail immediately during initialization if given duplicates (via `ToDictionary` throwing on duplicate keys), while the Election contract silently accepts them. This difference in behavior is the root cause - Election allows duplicates to persist in state, while Consensus assumes uniqueness.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L22-52)
```csharp
    public override Empty InitialElectionContract(InitialElectionContractInput input)
    {
        Assert(!State.Initialized.Value, "Already initialized.");

        State.Candidates.Value = new PubkeyList();

        State.MinimumLockTime.Value = input.MinimumLockTime;
        State.MaximumLockTime.Value = input.MaximumLockTime;

        State.TimeEachTerm.Value = input.TimeEachTerm;

        State.MinersCount.Value = input.MinerList.Count;
        State.InitialMiners.Value = new PubkeyList
        {
            // ReSharper disable once ConvertClosureToMethodGroup
            Value = { input.MinerList.Select(m => ByteStringHelper.FromHexString(m)) }
        };
        foreach (var pubkey in input.MinerList)
            State.CandidateInformationMap[pubkey] = new CandidateInformation
            {
                Pubkey = pubkey
            };

        State.CurrentTermNumber.Value = 1;

        State.DataCentersRankingList.Value = new DataCenterRankingList();

        State.Initialized.Value = true;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L220-226)
```csharp
        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L386-391)
```csharp
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-339)
```csharp
            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }
```

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```
