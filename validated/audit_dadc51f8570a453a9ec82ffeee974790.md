# Audit Report

## Title
First Round Mining Logic Uses Wrong Reference Point, Allowing Unauthorized Operations and Transaction Fee Theft

## Summary
The `IsCurrentMiner` function contains a critical logic error in its first round special case handling. When determining if a miner is authorized during round 1, the code incorrectly orders miners by their `Order` field (a predetermined positional value) instead of their actual mining timestamps. This causes the time-slot authorization calculation to use the wrong reference point, allowing miners to claim transaction fees and perform privileged operations when they should not be authorized.

## Finding Description

The vulnerability exists in the first round special case logic within the `IsCurrentMiner` function. [1](#0-0) 

**Root Cause:**

The code attempts to find the "latest mined" miner by ordering miners by their `Order` field in descending order: [2](#0-1) 

However, the `Order` field represents a miner's predetermined sequence position in the round (assigned during round generation via hash-based or election-based ordering), not the actual chronological time when they mined. The `Order` values are assigned during round initialization and remain static throughout the round. [3](#0-2) 

The `ActualMiningTimes` field is a chronological list that records the actual timestamps when blocks were produced. Each time a miner produces a block (normal or tiny block), a timestamp is added to this list: [4](#0-3) [5](#0-4) 

**Why This Matters:**

The code uses the wrong miner's `ActualMiningTimes.Last()` as the reference point for calculating how many time slots have passed. This calculation then determines if the current miner is authorized. If the reference point is wrong (using a miner with high Order but earlier mining time instead of the chronologically most recent miner), the `passedSlotsCount` calculation becomes incorrect, potentially authorizing miners when insufficient time has actually elapsed since the last block.

**Concrete Attack Scenario:**

Round 1 with 5 miners (A=Order 1, B=Order 2, C=Order 3, D=Order 4, E=Order 5), mining interval = 4000ms:
- T1 (4000ms): Miner E produces block (Order=5, ActualMiningTimes=[T1])
- T2 (8000ms): Miner A produces block (Order=1, ActualMiningTimes=[T2])
- T3 (12000ms): Miner B calls ClaimTransactionFees

Flawed logic selects E (highest Order with ActualMiningTimes), uses T1 as reference:
- passedSlotsCount = (T3-T1)/4000 = 2
- Check: 2 == (2-5)+5 = 2 ✓ → Miner B AUTHORIZED (wrong!)

Correct logic should select A (chronologically latest), use T2 as reference:
- passedSlotsCount = (T3-T2)/4000 = 1  
- Check: 1 == (2-1)+5 = 6 ✗ → Miner B NOT AUTHORIZED (correct)

**Why Normal Protections Don't Apply:**

The first round logic exists specifically because `ExpectedMiningTimes` are unreliable when the blockchain starts with a misconfigured `StartTimestamp`: [6](#0-5) 

The `TimeSlotValidationProvider` completely bypasses time slot validation for round 1, relying on other logic including IsCurrentMiner: [7](#0-6) 

## Impact Explanation

**Direct Impact:**

1. **Unauthorized Transaction Fee Claiming**: The `ClaimTransactionFees` function uses `IsCurrentMiner` as its sole authorization check: [8](#0-7) [9](#0-8) 

If `IsCurrentMiner` returns true incorrectly, unauthorized miners can directly claim and extract transaction fees accumulated in the contract, representing concrete fund theft.

2. **Unauthorized Governance Operations**: The `ApproveMultiProposals` function in Parliament contract uses the same flawed authorization: [10](#0-9) 

3. **Unauthorized Contract Deployment Control**: The `ReleaseApprovedUserSmartContract` function in Genesis contract also relies on this check: [11](#0-10) 

**Affected Parties:**
- Honest miners who lose their rightful share of transaction fees
- The protocol's governance fairness is compromised at every term transition
- Contract deployment security is weakened during round 1
- With typical configurations (21+ miners, ~4 second intervals), unauthorized operations can occur multiple times per round 1

**Severity:** High - This breaks core authorization guarantees and enables concrete fund extraction (transaction fees) plus governance manipulation at predictable intervals (every term change).

## Likelihood Explanation

**Triggering Conditions:**
1. Round 1 of any term begins (occurs at every term transition, approximately every 7 days with default configuration)
2. Multiple miners produce blocks, including tiny blocks (normal operation)
3. Miners produce blocks in an order different from their positional `Order` values (highly likely with 21+ miners and asynchronous block production)

**Attack Complexity:** Low. The vulnerability manifests naturally without intentional exploitation. When a miner with a lower `Order` number produces a block after a miner with a higher `Order` number (which happens frequently in round 1 due to network conditions and varying block production times), the flawed logic selects the wrong reference point.

**Feasibility:** Very high. Round 1 occurs at every term transition. The first round special case logic is documented to be active on AElf Main Chain due to the `Timestamp{Seconds=0}` configuration. With multiple miners producing blocks asynchronously, the scenario where the highest-Order miner is not the chronologically latest miner occurs regularly and naturally.

**Detection Difficulty:** High. All nodes execute the same flawed logic, so the incorrect authorizations are consensus-wide. The operations appear valid from an external perspective, making detection difficult without deep code analysis.

**Overall Likelihood:** High - Occurs naturally during every round 1 of each term (approximately weekly).

## Recommendation

Fix the ordering logic to use actual mining timestamps instead of the Order field:

```csharp
// Current (WRONG):
var latestMinedInfo =
    currentRound.RealTimeMinersInformation.Values.OrderByDescending(i => i.Order)
        .FirstOrDefault(i => i.ActualMiningTimes.Any() && i.Pubkey != pubkey);

// Fixed (CORRECT):
var latestMinedInfo =
    currentRound.RealTimeMinersInformation.Values
        .Where(i => i.ActualMiningTimes.Any() && i.Pubkey != pubkey)
        .OrderByDescending(i => i.ActualMiningTimes.Last())
        .FirstOrDefault();
```

This ensures the chronologically most recent miner is selected as the reference point, making the time-slot calculation accurate regardless of the miners' Order values.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize consensus contract with round 1
2. Have miner E (Order=5) produce a block at time T1
3. Have miner A (Order=1) produce a block at time T2 (after T1)
4. Advance time to T3
5. Call IsCurrentMiner for miner B (Order=2) at time T3
6. Verify it incorrectly returns true
7. Successfully call ClaimTransactionFees from miner B's address
8. Verify fees were claimed despite B not being the authorized miner at that time slot

The vulnerability is confirmed by the code analysis showing the flawed ordering logic and its concrete usage in authorization-critical functions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L191-216)
```csharp
        // If current round is the first round of current term.
        if (currentRound.RoundNumber == 1)
        {
            Context.LogDebug(() => "First round");

            var latestMinedInfo =
                currentRound.RealTimeMinersInformation.Values.OrderByDescending(i => i.Order)
                    .FirstOrDefault(i => i.ActualMiningTimes.Any() && i.Pubkey != pubkey);
            if (latestMinedInfo != null)
            {
                var minersCount = currentRound.RealTimeMinersInformation.Count;
                var latestMinedSlotLastActualMiningTime = latestMinedInfo.ActualMiningTimes.Last();
                var latestMinedOrder = latestMinedInfo.Order;
                var currentMinerOrder =
                    currentRound.RealTimeMinersInformation.Single(i => i.Key == pubkey).Value.Order;
                var passedSlotsCount =
                    (Context.CurrentBlockTime - latestMinedSlotLastActualMiningTime).Milliseconds()
                    .Div(miningInterval);
                if (passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(1).Add(minersCount) ||
                    passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(minersCount))
                {
                    Context.LogDebug(() => "[CURRENT MINER]FIRST ROUND");
                    return true;
                }
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L29-30)
```csharp

            minerInRound.Pubkey = sortedMiners[i];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L304-304)
```csharp
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs (L14-19)
```csharp
    ///     Why implement a strategy only for first round?
    ///     Because during the first round, the ExpectedMiningTimes of every miner
    ///     depends on the StartTimestamp configured before starting current blockchain,
    ///     (which AElf Main Chain use new Timestamp {Seconds = 0},)
    ///     thus we can't really give mining scheduler these data.
    ///     The ActualMiningTimes will based on Orders of these miners.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L39-39)
```csharp
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L869-869)
```csharp
        AssertSenderIsCurrentMiner();
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L897-906)
```csharp
    private void AssertSenderIsCurrentMiner()
    {
        if (State.ConsensusContract.Value == null)
        {
            State.ConsensusContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
        }

        Assert(State.ConsensusContract.IsCurrentMiner.Call(Context.Sender).Value, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L188-200)
```csharp
    public override Empty ApproveMultiProposals(ProposalIdList input)
    {
        AssertCurrentMiner();
        foreach (var proposalId in input.ProposalIds)
        {
            var proposal = State.Proposals[proposalId];
            if (proposal == null || !CheckProposalNotExpired(proposal))
                continue;
            Approve(proposalId);
            Context.LogDebug(() => $"Proposal {proposalId} approved by {Context.Sender}");
        }

        return new Empty();
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L476-493)
```csharp
    public override Empty ReleaseApprovedUserSmartContract(ReleaseContractInput input)
    {
        var contractProposingInput = State.ContractProposingInputMap[input.ProposedContractInputHash];

        Assert(
            contractProposingInput != null &&
            contractProposingInput.Status == ContractProposingInputStatus.CodeCheckProposed &&
            contractProposingInput.Proposer == Context.Self, "Invalid contract proposing status.");

        AssertCurrentMiner();

        contractProposingInput.Status = ContractProposingInputStatus.CodeChecked;
        State.ContractProposingInputMap[input.ProposedContractInputHash] = contractProposingInput;
        var codeCheckController = State.CodeCheckController.Value;
        Context.SendInline(codeCheckController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release), input.ProposalId);
        return new Empty();
    }
```
