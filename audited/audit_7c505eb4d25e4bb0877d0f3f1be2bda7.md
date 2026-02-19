### Title
Authorization Bypass via ExtraBlockProducerOfPreviousRound During Term Transition Window

### Summary
The `IsCurrentMiner` function allows the `ExtraBlockProducerOfPreviousRound` to bypass authorization checks during term transitions when the miner list changes. A former miner who is excluded from the new term's miner list can exploit a predictable time window to claim transaction fees and perform privileged cross-chain operations, violating the invariant that only current miners should have these privileges.

### Finding Description

The vulnerability exists in the `IsCurrentMiner` function where two security checks interact incorrectly: [1](#0-0) 

When `IsMinerListJustChanged` is true (during term transitions), the validation that verifies `pubkey` exists in `currentRound.RealTimeMinersInformation` is skipped. The code then proceeds to check: [2](#0-1) 

This allows any miner who was the `ExtraBlockProducerOfPreviousRound` to pass the authorization check if `Context.CurrentBlockTime <= currentRound.GetRoundStartTime()`, regardless of whether they are in the new miner list.

The `ExtraBlockProducerOfPreviousRound` is set during round generation: [3](#0-2) 

When a new term starts with changed miner list: [4](#0-3) 

The round start time is set to `miningInterval` milliseconds after the current block time: [5](#0-4) 

**Root Cause**: The function incorrectly prioritizes the `ExtraBlockProducerOfPreviousRound` privilege over current miner list membership validation during term transitions.

**Why Protections Fail**: The miner list membership check at lines 142-144 is conditional and skipped when `IsMinerListJustChanged == true`, creating an authorization bypass for the previous extra block producer.

### Impact Explanation

**Direct Fund Impact**: 
The `IsCurrentMiner` check is used as the sole authorization mechanism for claiming transaction fees: [6](#0-5) [7](#0-6) 

A former miner excluded from the new term can claim transaction fees that should only be claimable by current miners, directly stealing funds meant for legitimate miners.

**Consensus/Cross-Chain Integrity Impact**:
The same authorization check controls cross-chain operations: [8](#0-7) [9](#0-8) 

This allows unauthorized miners to propose and release cross-chain indexing data, potentially corrupting cross-chain synchronization.

**Who is Affected**: All miners in the new term lose potential fee revenue, and cross-chain integrity can be compromised if malicious data is indexed.

**Severity Justification**: HIGH - Direct fund theft, authorization bypass for critical consensus operations, and cross-chain integrity violation.

### Likelihood Explanation

**Attacker Capabilities**: Attacker must have been a legitimate miner in the previous term who produced the term-transition block, making them the `ExtraBlockProducerOfPreviousRound`.

**Attack Complexity**: LOW
1. Wait for term transition where attacker is excluded from new miner list
2. Submit transaction calling `ClaimTransactionFees` or `ProposeCrossChainIndexing` immediately after transition
3. Transaction must be included in a block during the predictable window (lasts `miningInterval` milliseconds, typically 4000ms)

**Feasibility Conditions**:
- Term transitions occur regularly (every period, typically 7 days)
- Miner list changes are common in AEDPoS when elections occur
- The exploitation window is deterministic and easily calculable: [10](#0-9) 

**Detection/Operational Constraints**: The attacker's transaction appears legitimate during execution since `IsCurrentMiner` returns true. No special privileges beyond submitting a transaction are required during the window.

**Probability**: HIGH - Occurs naturally during every term transition where the previous extra block producer is not re-elected. The time window is sufficient for transaction submission and inclusion.

### Recommendation

**Code-Level Mitigation**:

Modify the `IsCurrentMiner` function to always verify miner list membership, even when checking `ExtraBlockProducerOfPreviousRound`:

```csharp
// Check confirmed extra block producer of previous round.
if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
    currentRound.ExtraBlockProducerOfPreviousRound == pubkey &&
    currentRound.RealTimeMinersInformation.ContainsKey(pubkey)) // Add this check
{
    Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
    return true;
}
```

This ensures the `ExtraBlockProducerOfPreviousRound` must also be in the current round's miner list to pass authorization.

**Invariant Check to Add**: Assert that any miner passing `IsCurrentMiner` during term transitions must be present in the current round's `RealTimeMinersInformation` dictionary.

**Test Cases to Prevent Regression**:
1. Test term transition where `ExtraBlockProducerOfPreviousRound` is excluded from new miner list
2. Verify that excluded miner cannot call `ClaimTransactionFees` during transition window
3. Verify that excluded miner cannot call `ProposeCrossChainIndexing` during transition window
4. Ensure legitimate new miners can still perform these operations

### Proof of Concept

**Required Initial State**:
- Term N active with miners [A, B, C, D, E]
- Miner A produces the block that transitions to Term N+1
- Term N+1 miner list is [F, G, H, I, J] (Miner A excluded)
- Mining interval is 4000ms

**Transaction Steps**:

1. **Term Transition Block (Height H)**:
   - Miner A includes `NextTerm` transaction
   - `GenerateFirstRoundOfNextTerm` executes, setting `ExtraBlockProducerOfPreviousRound = A`
   - New round stored with `IsMinerListJustChanged = true`
   - Block time T, new round start time T + 4000ms

2. **Exploitation Window (Height H+1 to H+N, Time T to T+4000ms)**:
   - Miner A submits transaction calling `ClaimTransactionFees(fees_map)`
   - Transaction included by new miner F
   - Block time is T + 2000ms (within window)

3. **Transaction Execution**:
   - `ClaimTransactionFees` calls `AssertSenderIsCurrentMiner()`
   - `IsCurrentMiner(A)` is invoked
   - Line 142-144: Check skipped (`IsMinerListJustChanged == true`)
   - Line 150-155: Returns `true` (T + 2000ms <= T + 4000ms, and A == `ExtraBlockProducerOfPreviousRound`)
   - Authorization passes, fees claimed by Miner A

**Expected vs Actual Result**:
- **Expected**: Miner A's transaction should fail with "No permission" error since A is not in current miner list
- **Actual**: Transaction succeeds, Miner A claims fees despite not being a current miner

**Success Condition**: Miner A receives transaction fees in their balance, event `TransactionFeeClaimed` is fired with Miner A's address, despite A not being in Term N+1's miner list.

### Notes

The vulnerability specifically manifests during term transitions due to the `IsMinerListJustChanged` flag, which is set when generating the first round of a new term. The design intent appears to allow the previous extra block producer to continue operations during the brief transition period, but this creates an unintended authorization bypass that persists for the entire mining interval window. The issue is particularly severe because it bypasses authorization for financial operations (`ClaimTransactionFees`) and critical cross-chain operations, not just consensus block production.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L142-144)
```csharp
        if (!currentRound.IsMinerListJustChanged)
            if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
                return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L254-254)
```csharp
        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L32-33)
```csharp
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L105-108)
```csharp
    public Timestamp GetRoundStartTime()
    {
        return FirstMiner().ExpectedMiningTime;
    }
```
