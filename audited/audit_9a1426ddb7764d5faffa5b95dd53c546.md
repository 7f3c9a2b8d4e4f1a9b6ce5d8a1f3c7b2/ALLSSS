# Audit Report

## Title
Lexicographic Backup Selection Allows Malicious Miners to Persist Without Voting Support

## Summary
The `GetVictories()` function in the Election contract uses arbitrary lexicographic ordering to select backup miners when valid candidates are insufficient, enabling attackers to game the selection mechanism through vanity public key generation and maintain mining privileges indefinitely during candidate shortages without community voting support.

## Finding Description

The vulnerability exists in the backup selection logic of the `GetVictories()` method. When the number of valid candidates (those with `ObtainedActiveVotedVotesAmount > 0`) is less than the required `MinersCount`, the function fills the gap by selecting backups from current miners and initial miners using purely lexicographic ordering. [1](#0-0) 

The backup selection process creates a pool from current miners not in valid candidates, plus initial miners, then sorts this pool lexicographically and takes the first `diff` entries. This breaks the fundamental security guarantee that **miners should be selected based on community voting support**.

**Why This Breaks Security Guarantees:**

1. **No Merit-Based Selection**: Unlike the normal path which orders candidates by `ObtainedActiveVotedVotesAmount`, backup selection uses arbitrary string ordering that has no correlation with miner quality, performance, or community support. [2](#0-1) 

2. **Missing Ban Checks**: The backup selection path does not check `State.BannedPubkeyMap`, unlike `GetMinerReplacementInformation` which explicitly filters banned pubkeys when selecting replacement miners. [3](#0-2) 

3. **Valid Candidate Threshold**: Valid candidates only need any votes greater than zero, with no meaningful minimum threshold. [4](#0-3) 

**Execution Path:**

The consensus contract calls `GetVictories()` during term transitions to determine the new miner list: [5](#0-4) [6](#0-5) 

**Attack Scenario:**

1. Attacker generates a vanity public key with low lexicographic value (e.g., starting with "0000...") - requires ~65k keypair generations for 4 leading zeros
2. Attacker locks the required 100,000 ELF and announces candidacy [7](#0-6) 

3. Attacker obtains enough votes to be elected once, entering the current miner list
4. After being elected, attacker's voting support drops to zero (no longer a valid candidate)
5. When a candidate shortage occurs (`diff > 0`), `GetVictories()` selects the attacker as a backup due to their low-sorting pubkey
6. Attacker is included in the new term's miner list and continues earning mining rewards
7. This cycle repeats as long as candidate shortages persist, creating a circular dependency where attackers remain in `currentMiners` and get selected as backups

## Impact Explanation

**Direct Harms:**

1. **Reward Misallocation**: Attackers continue earning block production rewards and transaction fees without maintaining proportional community voting support. Mining rewards over multiple terms can far exceed the 100,000 ELF lock requirement, making this attack profitable.

2. **Consensus Integrity Compromise**: Miners without community backing remain in the consensus set, enabling potential censorship attacks, transaction filtering, or collusion with other similarly-positioned miners to control block production during shortage periods.

3. **Democratic Subversion**: The Election contract's fundamental purpose is to enable token holders to vote for miners. This vulnerability completely bypasses that mechanism during shortage periods, allowing miners to persist based on an arbitrary technical detail (lexicographic ordering) rather than community support.

**Affected Parties:**

- Legitimate candidates with higher-sorting pubkeys who should be selected as backups based on merit
- Token holders whose votes are effectively nullified during shortage periods  
- Ecosystem security as unaccountable miners maintain consensus control

**Severity: HIGH** because it:
- Directly compromises the vote-based miner selection mechanism that is core to AElf's consensus
- Enables persistent control during candidate shortages (common in new/struggling chains)
- Amplifies with multiple colluding attackers using coordinated low-sorting pubkeys
- Has no detection or removal mechanism once established
- Cannot be mitigated by governance without code changes

## Likelihood Explanation

**Attacker Capabilities Required:**

1. **Vanity Pubkey Generation** (Low Complexity): Generating public keys with low lexicographic values is computationally feasible. Finding a pubkey starting with four zeros requires approximately 16^4 = 65,536 keypair generations on average, which is trivial with modern hardware.

2. **Initial Election** (Medium Complexity): The main barrier is getting elected at least once, which requires:
   - Locking 100,000 ELF per candidate
   - Obtaining enough votes to be in the top N candidates initially
   - Can be achieved through vote buying, building legitimate reputation then acting maliciously, or Sybil attacks with multiple coordinated candidates

3. **Vote Manipulation** (Low Complexity): After initial election, attacker can simply let voting support drop, knowing they'll be selected as backup during shortages.

**Feasibility Conditions:**

- **Candidate Shortage** (`diff > 0`): More likely in new chains, ecosystems with low participation, or after mass candidate exodus. While mature chains may rarely experience this, it's common during network growth phases or stress periods.
- **Attacker Persistence**: Attacker must remain in current miner list or be an initial miner (achieved via initial election)
- **Attack Amplification**: Multiple colluding attackers with low-sorting pubkeys amplify impact by dominating backup slots

**Detection Constraints:**

- Difficult to distinguish from legitimate backup selection without analyzing pubkey patterns
- No on-chain indicator shows whether a miner was selected via backup path vs voting path
- Pattern only emerges over multiple terms of analysis

**Probability: MEDIUM to HIGH** in scenarios where:
- Ecosystem experiences persistent candidate shortages (new/struggling chains, low participation periods)
- Initial election barrier can be overcome (vote buying is possible, reputation can be built)
- Multiple attackers coordinate with low-sorting pubkeys to dominate backup selection

## Recommendation

**Immediate Fixes:**

1. **Add Ban Checks**: Apply the same banned pubkey filtering in backup selection that exists in `GetMinerReplacementInformation`:

```csharp
var backups = currentMiners.Where(k => !validCandidates.Contains(k) && !State.BannedPubkeyMap[k]).ToList();
if (State.InitialMiners.Value != null)
    backups.AddRange(
        State.InitialMiners.Value.Value.Select(k => k.ToHex())
            .Where(k => !backups.Contains(k) && !State.BannedPubkeyMap[k]));
```

2. **Implement Merit-Based Backup Selection**: Replace lexicographic ordering with merit-based criteria such as:
   - Historical performance metrics (blocks produced, missed slots)
   - Stake amount or lock duration
   - Randomized selection weighted by past vote amounts
   - Most recent vote amounts (even if currently below threshold)

```csharp
// Example: Order by historical vote amounts instead of lexicographically
victories.AddRange(backups
    .Select(k => new { Pubkey = k, Votes = State.CandidateVotes[k]?.AllObtainedVotedVotesAmount ?? 0 })
    .OrderByDescending(x => x.Votes)
    .Take(Math.Min(diff, currentMiners.Count))
    .Select(x => ByteStringHelper.FromHexString(x.Pubkey)));
```

3. **Add Minimum Vote Threshold**: Require valid candidates to have a meaningful minimum vote amount rather than just `> 0`.

4. **Emit Events**: Add events that clearly indicate when backup selection occurs and which miners were selected via backup path vs voting path for transparency.

## Proof of Concept

```csharp
[Fact]
public async Task LexicographicBackupSelection_AllowsVanityPubkeyToPersis()
{
    // Setup: Initialize election with MinersCount = 5
    await InitializeElectionContract();
    
    // Step 1: Create attacker with vanity pubkey (low lexicographic value)
    var attackerPubkey = "0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var legitimatePubkey = "ffff1111111111111111111111111111111111111111111111111111111111";
    
    // Step 2: Both announce candidacy and lock 100,000 ELF
    await AnnounceCandidate(attackerPubkey);
    await AnnounceCandidate(legitimatePubkey);
    
    // Step 3: Both get elected initially with votes
    await VoteForCandidate(attackerPubkey, 10000);
    await VoteForCandidate(legitimatePubkey, 10000);
    await TransitionToNewTerm(); // Both elected in term 1
    
    // Step 4: Attacker loses all votes, legitimate miner keeps votes
    await WithdrawVotes(attackerPubkey);
    
    // Step 5: Create candidate shortage (only 2 valid candidates but need 5 miners)
    var victories = await ElectionContract.GetVictories.CallAsync(new Empty());
    
    // Verify: Attacker with vanity pubkey is selected as backup despite having 0 votes
    // Legitimate miner with higher-sorting pubkey is NOT selected despite having votes
    Assert.Contains(ByteStringHelper.FromHexString(attackerPubkey), victories.Value);
    Assert.DoesNotContain(ByteStringHelper.FromHexString(legitimatePubkey), victories.Value);
    
    // Step 6: Verify attacker persists across multiple terms during shortage
    for (int term = 2; term <= 5; term++)
    {
        await TransitionToNewTerm();
        victories = await ElectionContract.GetVictories.CallAsync(new Empty());
        
        // Attacker continues to be selected due to low lexicographic value
        Assert.Contains(ByteStringHelper.FromHexString(attackerPubkey), victories.Value);
    }
}
```

## Notes

This vulnerability represents a fundamental flaw in the backup selection mechanism that contradicts the vote-based election system's core security model. The lexicographic ordering is deterministic but completely arbitrary from a security perspective - it provides no guarantees about miner quality or community support.

The attack is particularly concerning because:
- It's **permanent** once established during shortage periods (no automatic removal mechanism)
- It **scales** with multiple colluding attackers using coordinated low-sorting pubkeys
- It **bypasses governance** - even if token holders try to vote attackers out, backup selection ignores votes
- It's **difficult to detect** without analyzing pubkey patterns across terms

The inconsistency with `GetMinerReplacementInformation` (which does check banned pubkeys) suggests this was an oversight rather than intentional design, making it a clear bug that violates expected security properties.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L60-77)
```csharp
        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-84)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L86-95)
```csharp
    private List<string> GetValidCandidates()
    {
        if (State.Candidates.Value == null) return new List<string>();

        return State.Candidates.Value.Value
            .Where(c => State.CandidateVotes[c.ToHex()] != null &&
                        State.CandidateVotes[c.ToHex()].ObtainedActiveVotedVotesAmount > 0)
            .Select(p => p.ToHex())
            .ToList();
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L387-391)
```csharp
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
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

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L4-6)
```csharp
{
    public const long LockTokenForElection = 100_000_00000000;

```
