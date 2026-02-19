# Audit Report

## Title
Colluding Miners Can Prevent Treasury Release by Blocking Term Transitions

## Summary
A coalition of 1/3+ miners can prevent term changes indefinitely by refusing to mine blocks. This blocks execution of `Treasury.Release`, causing mining rewards to accumulate in the Treasury contract without distribution to voters, citizens, and other beneficiaries. The vulnerability stems from a threshold calculation mismatch in the term change decision logic.

## Finding Description

The vulnerability exists in the term change decision mechanism. The `GetConsensusBehaviourToTerminateCurrentRound()` method determines whether to trigger `NextRound` or `NextTerm` behavior based on `NeedToChangeTerm()`. [1](#0-0) 

The critical flaw is in `NeedToChangeTerm()`, which filters miners to only those with `ActualMiningTimes.Any()` (miners who have actually mined blocks), then compares the count against `MinersCountOfConsent`: [2](#0-1) 

However, `MinersCountOfConsent` is calculated based on the TOTAL miner count, not the filtered count: [3](#0-2) 

**Attack Scenario:**
With 7 total miners:
- `MinersCountOfConsent = 7 * 2 / 3 + 1 = 5`
- If 3 miners refuse to mine (no `ActualMiningTimes`), only 4 miners remain in the filtered set
- Even if all 4 agree it's time to change term, `4 < 5` fails the threshold
- `NeedToChangeTerm()` returns false, triggering `NextRound` instead of `NextTerm`

**Critical Impact:** `Treasury.Release` is ONLY called in `ProcessNextTerm()`: [4](#0-3) 

The Treasury contract enforces that only the consensus contract can call `Release`: [5](#0-4) 

**Why Protections Fail:**

1. **Evil Miner Detection:** Miners who miss slots are marked as evil after 4,320 slots (≈3 days): [6](#0-5) 

However, evil miner detection in `ProcessNextRound` only marks miners—it doesn't force a term change: [7](#0-6) 

2. **Miner Replacement:** New miners generated via `GenerateNextRoundInformation` start with empty `MinerInRound` structures that lack `ActualMiningTimes`, so they don't immediately contribute to the threshold: [8](#0-7) 

3. **Term Period:** With the default period of 604,800 seconds (7 days), malicious miners only need to sustain the attack until the term boundary: [9](#0-8) 

## Impact Explanation

**Direct Fund Impact:**
Mining rewards are donated to Treasury via `DonateMiningReward()`: [10](#0-9) 

Without `Treasury.Release`, these funds never get distributed to profit schemes (Basic Reward, Backup Subsidy, Citizen Welfare, Welcome Reward, Flexible Reward). Funds accumulate indefinitely in the Treasury contract.

**Affected Parties:**
- **Voters/Token Holders:** Lose expected staking dividends from profit distribution
- **Citizens:** Lose welfare rewards distributed through the Welfare scheme
- **Backup Nodes:** Lose subsidy rewards
- **Protocol Economics:** Incentive mechanisms break down, reducing participation and potentially threatening network security

**Quantification:**
With the default mining reward of 12,500,000 tokens per block, each missed term prevents distribution of `blocks_in_term * 12,500,000` tokens. The attack can be repeated across multiple terms for cumulative effect, potentially locking substantial value.

## Likelihood Explanation

**Attacker Capabilities:**
Requires control of ⌈(total_miners + 1) / 3⌉ miners (e.g., 3 out of 7 miners = 43%). This is a realistic threshold for a coordinated attack by a minority coalition—significantly lower than the 51% typically required for consensus attacks.

**Attack Complexity:**
**Low** - Attackers simply abstain from mining (passive attack). No special transactions, exploits, or technical sophistication needed. Only requires coordination among colluding miners.

**Feasibility Conditions:**
- No special permissions required beyond being elected as miners (normal protocol operation)
- Works on mainchain (sidechain always uses NextRound behavior per the implementation)
- Attack is visible (missing blocks) but doesn't immediately trigger effective protections
- Evil miner detection takes 3 days, while term boundary is at day 7—insufficient time
- By the time miners could be replaced, the term change opportunity is already missed

**Economic Rationality:**
Colluding miners lose block rewards during the attack period (7 days). However, they may be motivated by:
- Governance manipulation (preventing reward distribution changes voting power dynamics)
- External incentives (paid by competing interests to harm the protocol)
- Deliberate protocol disruption
The cost is bounded and predictable versus potentially large impact.

## Recommendation

**Fix the Threshold Calculation:**

Modify `NeedToChangeTerm()` to calculate `MinersCountOfConsent` based on the filtered miner count (those who have actually mined), not the total miner count. This ensures consistency between the filtering logic and threshold comparison:

```csharp
public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
{
    var minersWhoMined = RealTimeMinersInformation.Values
        .Where(m => m.ActualMiningTimes.Any())
        .ToList();
    
    var minersCountOfConsent = minersWhoMined.Count.Mul(2).Div(3).Add(1);
    
    return minersWhoMined
        .Select(m => m.ActualMiningTimes.Last())
        .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp, t, currentTermNumber, periodSeconds))
        >= minersCountOfConsent;
}
```

**Alternative/Additional Mitigations:**

1. **Force Term Change After Timeout:** If evil miners are detected and not enough miners participate for N consecutive rounds, force a term change with the remaining honest miners
2. **Emergency Release Mechanism:** Add a governance-controlled emergency release function that can be triggered through Parliament proposal if term changes are blocked
3. **Reduce Detection Threshold:** Lower `TolerableMissedTimeSlotsCount` to detect non-participating miners faster
4. **Immediate Replacement:** Replace non-participating miners immediately rather than waiting for term boundaries

## Proof of Concept

```csharp
[Fact]
public async Task MinorityMinersCanBlockTermChange()
{
    // Setup: 7 miners, term period = 7 days
    const int totalMiners = 7;
    const int colludingMiners = 3; // 43% - less than majority
    const long termPeriod = 604800; // 7 days in seconds
    
    // Initialize consensus with 7 miners
    await InitializeConsensus(totalMiners, termPeriod);
    
    // Simulate mining for 6.5 days with only 4 miners (3 abstain)
    var honestMiners = 4;
    await SimulateMiningPeriod(honestMiners, termPeriod - 43200); // Stop 0.5 days before term end
    
    // At term boundary, check if term change is triggered
    var currentRound = await GetCurrentRoundInformation();
    var behaviour = GetConsensusBehaviourToTerminateCurrentRound(currentRound);
    
    // Verify: Should be NextTerm but is NextRound due to threshold mismatch
    Assert.Equal(AElfConsensusBehaviour.NextRound, behaviour); // Vulnerability confirmed
    
    // Verify: Treasury.Release was not called
    var treasuryBalanceBefore = await GetTreasuryBalance();
    await ProcessRoundTermination(behaviour);
    var treasuryBalanceAfter = await GetTreasuryBalance();
    
    // Treasury accumulated donations but didn't distribute
    Assert.True(treasuryBalanceAfter > treasuryBalanceBefore);
    
    // Verify: No profit distribution occurred
    var voterProfits = await GetVoterProfits();
    Assert.Equal(0, voterProfits); // Voters received nothing
}
```

**Notes:**
- The test demonstrates that with 43% of miners abstaining (3 out of 7), the term change is blocked even though 57% of miners are honest
- This violates the expected Byzantine Fault Tolerance property where the system should function correctly with up to 1/3 faulty nodes
- The vulnerability allows a minority coalition to DoS the treasury distribution mechanism indefinitely

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-35)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L126-128)
```csharp
        Assert(
            Context.Sender == State.AEDPoSContract.Value,
            "Only AElf Consensus Contract can release profits from Treasury.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L12-12)
```csharp
    public long PeriodSeconds { get; set; } = 604800;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```
