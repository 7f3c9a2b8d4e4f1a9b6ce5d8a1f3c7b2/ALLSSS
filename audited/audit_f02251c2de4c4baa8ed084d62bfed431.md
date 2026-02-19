### Title
Solitary Miner Detection Bypass via Two-Miner Collusion or Network Partition

### Summary
The `SolitaryMinerDetection()` function is designed to prevent isolated miners from building long forks during network partitions by checking if a single miner has been mining alone for 2+ consecutive rounds. However, two or more miners can bypass this detection by either alternating block production or mining together, allowing a minority partition to continue producing blocks indefinitely without triggering the safety mechanism.

### Finding Description

The vulnerability exists in the `SolitaryMinerDetection()` function [1](#0-0) 

The detection logic requires that the **same miner** mined alone in both the previous round and the round before that: [2](#0-1) [3](#0-2) 

The root cause is that the check validates `minedMiners.Count == 1 && minedMiners.Select(m => m.Pubkey).Contains(pubkey)` - requiring both that only one miner mined AND that miner is the current one attempting to mine.

**Bypass Method 1: Alternating Mining**
- Round N-2: Miner A mines alone (Count=1, miners=[A])
- Round N-1: Miner B mines alone (Count=1, miners=[B])  
- Round N: When A tries to mine, check fails because previous round contains B's pubkey, not A's
- Round N: When B tries to mine, check fails because round N-2 contains A's pubkey, not B's

**Bypass Method 2: Concurrent Mining**
- Rounds N-2, N-1: Both A and B mine (Count=2)
- Check immediately fails at `minedMiners.Count == 1` condition

The function is called before consensus command generation [4](#0-3)  and when it fails to detect isolation, mining continues normally.

### Impact Explanation

**Consensus Integrity Impact:**
- During a network partition, a minority group of 2+ miners can continue producing blocks without triggering the safety mechanism
- This creates a longer minority fork than the design intends, potentially reaching significant heights before partition resolution
- According to the AEDPoS design, the system requires 2N+1 miners (starting at 17 miners) [5](#0-4) , meaning a partition with 2-8 miners could bypass detection while the majority continues on another fork
- When the partition heals, the longest chain rule applies [6](#0-5) , causing a chain reorganization that discards the minority fork's blocks and transactions

**Operational Impact:**
- Users on the minority partition may see confirmed transactions that later get reverted when the partition heals
- Increased chain reorganization depth compared to early detection
- Wasted computational resources on the minority fork
- Potential economic losses for users who acted on minority chain state

**Severity Justification:** Medium - The vulnerability weakens a critical safety mechanism but doesn't directly enable fund theft. The eventual resolution follows correct consensus rules (longest chain wins), but the detection failure allows longer forks than intended.

### Likelihood Explanation

**Attacker Capabilities:**
- **Malicious Collusion:** Two or more miners intentionally coordinate to bypass detection and build a fork
- **Network Partition:** Legitimate scenario where 2+ miners are isolated together due to network issues

**Attack Complexity:**
- Low - Requires only alternating block production or concurrent mining by 2+ miners
- No special permissions beyond being elected miners
- No complex transaction sequences or state manipulation needed

**Feasibility Conditions:**
- Network partitions are common in distributed systems
- The AEDPoS system explicitly acknowledges this risk [7](#0-6) 
- Two malicious miners (out of 17+) is a realistic threat model below the 1/3 Byzantine tolerance threshold
- The detection is meant to activate "until 4th round" with "more than 2" total miners configured [8](#0-7)  - conditions frequently met in production

**Economic Rationality:**
- For malicious miners: Building a minority fork could be used for double-spend attempts or to disrupt service
- For network partition: No intentional attack, just failure of safety mechanism to operate as designed

**Probability Assessment:** Medium-High - Network partitions are inevitable in distributed systems, and the attack requires minimal coordination between just 2 miners.

### Recommendation

**Code-Level Mitigation:**
Modify `SolitaryMinerDetection()` to check the **total number of unique miners** across recent rounds rather than requiring the same single miner:

```csharp
private bool SolitaryMinerDetection(Round currentRound, string pubkey)
{
    var isAlone = false;
    if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
    {
        var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
        isAlone = minedMinersOfCurrentRound.Count == 0;

        if (TryToGetPreviousRoundInformation(out var previousRound) && isAlone)
        {
            var uniqueMinersSet = new HashSet<string>();
            
            // Collect unique miners from previous round
            var previousMiners = previousRound.GetMinedMiners();
            foreach (var miner in previousMiners)
                uniqueMinersSet.Add(miner.Pubkey);
            
            // Collect unique miners from two rounds ago
            if (TryToGetRoundInformation(previousRound.RoundNumber.Sub(1), 
                out var previousPreviousRound))
            {
                var previousPreviousMiners = previousPreviousRound.GetMinedMiners();
                foreach (var miner in previousPreviousMiners)
                    uniqueMinersSet.Add(miner.Pubkey);
            }
            
            // Check if total unique miners is below consensus threshold
            var minersCountThreshold = currentRound.MinersCountOfConsent;
            isAlone = uniqueMinersSet.Count > 0 && 
                     uniqueMinersSet.Count < minersCountThreshold &&
                     uniqueMinersSet.Contains(pubkey);
        }
    }
    return isAlone;
}
```

**Invariant Checks:**
- Total unique miners across last 2-3 rounds must be >= `MinersCountOfConsent` [9](#0-8)  (2/3 + 1 of total miners)
- Detection should trigger when minority partition has insufficient miners for consensus regardless of alternation patterns

**Test Cases to Add:**
1. Test with 2 miners alternating block production across 3+ rounds
2. Test with 2 miners both mining concurrently across 3+ rounds  
3. Test with 3 miners in minority partition (below 2/3 threshold)
4. Verify detection triggers when unique miner count < MinersCountOfConsent
5. Verify normal operation continues when unique miner count >= MinersCountOfConsent

### Proof of Concept

**Required Initial State:**
- AEDPoS consensus with 5 total miners (A, B, C, D, E) configured
- Round number > 3 (detection active)
- MinersCountOfConsent = 5 * 2/3 + 1 = 4 miners required

**Attack Sequence (Alternating):**

1. **Round N-2:** Network partition occurs. Miners A and B isolated together. Only A produces block.
   - `previousPreviousRound.GetMinedMiners()` returns [A], Count=1

2. **Round N-1:** Only B produces block on isolated partition.
   - `previousRound.GetMinedMiners()` returns [B], Count=1

3. **Round N:** Miner A attempts to mine.
   - Detection check for A:
     - `minedMinersOfCurrentRound.Count == 0` ✓ (TRUE)
     - Previous round check: `minedMiners.Count == 1` ✓ AND `Contains(A)` ✗ (contains B only)
     - Result: `isAlone = FALSE`
   - **Expected:** Detection should trigger (only 2 unique miners < 4 required)
   - **Actual:** Detection bypassed, A mines successfully

4. **Round N:** Miner B attempts to mine later.
   - Detection check for B:
     - Previous round: `Count == 1` ✓ AND `Contains(B)` ✓ 
     - Round N-2 check: `Count == 1` ✓ AND `Contains(B)` ✗ (contains A only)
     - Result: `isAlone = FALSE`
   - **Expected:** Detection should trigger
   - **Actual:** Detection bypassed, B mines successfully

**Success Condition:** Both miners A and B continue producing blocks on the minority partition without triggering `InvalidConsensusCommand`, allowing the fork to grow indefinitely until network partition heals.

**Notes**

The vulnerability fundamentally stems from checking if ONE specific miner dominated recent rounds, rather than checking if the TOTAL number of unique active miners falls below the consensus threshold. The comment describes the intent as detecting when "current miner mined blocks only himself for 2 rounds" [10](#0-9)  - but this narrow focus misses the broader network partition scenario where multiple miners are isolated together.

The 2/3 consensus threshold (`MinersCountOfConsent`) [9](#0-8)  is already used elsewhere in the codebase for irreversible block height calculations, and should be leveraged here for consistent safety guarantees across the consensus mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L23-24)
```csharp
        if (SolitaryMinerDetection(currentRound, pubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L59-61)
```csharp
    /// <summary>
    ///     If current miner mined blocks only himself for 2 rounds,
    ///     just stop and waiting to execute other miners' blocks.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L66-96)
```csharp
    private bool SolitaryMinerDetection(Round currentRound, string pubkey)
    {
        var isAlone = false;
        // Skip this detection until 4th round.
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
        {
            // Not single node.

            var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
            isAlone = minedMinersOfCurrentRound.Count == 0;

            // If only this node mined during previous round, stop mining.
            if (TryToGetPreviousRoundInformation(out var previousRound) && isAlone)
            {
                var minedMiners = previousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }

            // check one further round.
            if (isAlone && TryToGetRoundInformation(previousRound.RoundNumber.Sub(1),
                    out var previousPreviousRound))
            {
                var minedMiners = previousPreviousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }
        }

        return isAlone;
    }
```

**File:** docs/public-chain/dpos.md (L12-12)
```markdown
The heart of any blockchain system is those entities that produce blocks. The block producers form a finite set of 2N+1 mining nodes. It was decided that N would start at 8 for the public chain and increases by one every year, so every year two extra block producers can be elected compared to the previous year. These nodes in the AElf system follow and enforce all of the consensus rules defined by the system.
```

**File:** docs/public-chain/dpos.md (L38-40)
```markdown
One important aspect of the rules of consensus is that they must be resistant to a certain amount of naturally occurring events such as network lag, faulty nodes, and also malicious actors attempting to cheat the system. 

In the event that one or more of these problems occur, the non-malicious nodes must still be able to reach consensus - meaning that they eventually will agree on which chain to follow. At least ⅓ of the nodes have to be honest and well functioning for the systems to work, and as long this is true, the block producers will always end up agreeing.
```

**File:** docs/public-chain/dpos.md (L42-42)
```markdown
A node following AElf consensus will choose the longest chain in the event of forks, so this means that even if there is lag or even a network split when the faulty nodes recover a normal situation, they'll switch to follow the longest chain. The longest chain will be produced by the largest group of block producers (more precisely, block producers following the same rules and agreeing on the same blocks).
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```
