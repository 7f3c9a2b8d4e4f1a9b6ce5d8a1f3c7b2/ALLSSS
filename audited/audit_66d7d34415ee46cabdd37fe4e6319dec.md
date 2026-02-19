### Title
Integer Division in LastBlockOfCurrentTermMiningLimit Calculation Can Result in Zero Mining Limit, Preventing Term Transition Blocks

### Summary
The `LastBlockOfCurrentTermMiningLimit` calculation uses integer division that can result in 0 milliseconds when `MiningInterval` is less than 5ms. There is no validation preventing such small values during chain initialization, which would cause all term transition blocks to fail mining validation, effectively halting the blockchain at term boundaries.

### Finding Description

The vulnerability exists in the mining limit calculation for term transition blocks. The `LastBlockOfCurrentTermMiningLimit` property uses integer division: [1](#0-0) 

When `MiningInterval` is less than 5 (specifically 1-4 milliseconds), this calculation produces:
- MiningInterval = 1: 1 * 3 / 5 = 0
- MiningInterval = 2: 2 * 3 / 5 = 1
- MiningInterval = 3: 3 * 3 / 5 = 1
- MiningInterval = 4: 4 * 3 / 5 = 2

This limit is used when generating consensus commands for term transitions: [2](#0-1) 

The `MiningInterval` value is set during genesis initialization without minimum value validation: [3](#0-2) 

The only existing validation checks that mining interval is greater than 0, not greater than or equal to 5: [4](#0-3) 

The configuration source also lacks validation: [5](#0-4) 

When the mining limit is 0, the block mining validation fails because there is insufficient time allocated for block execution: [6](#0-5) 

The calculated mining duration becomes `blockTime + 0 - currentTime`, which is typically negative or insufficient by the time mining validation executes, causing the check at line 59 to fail and mining to be canceled: [7](#0-6) 

### Impact Explanation

**Operational Impact - Chain Halt at Term Boundaries:**

If the blockchain is initialized with a `MiningInterval` less than 5ms, all attempts to produce term transition blocks will fail. The validation in `ValidateBlockMiningTime` will consistently reject these blocks because the allocated execution time (0ms) is insufficient.

When term transition time arrives, the chain will be unable to:
1. Advance to the next term
2. Update the miner list based on election results
3. Continue normal block production beyond the term boundary

This results in a complete denial of service at term boundaries. The chain would effectively freeze, unable to progress past the current term. All miners would repeatedly fail to produce the term transition block, and the consensus mechanism would be stuck in an infinite retry loop.

**Severity Justification:** This is a high-impact operational vulnerability that causes complete chain halt, though with low likelihood due to genesis configuration control.

### Likelihood Explanation

**Preconditions:**
The vulnerability requires the blockchain to be initialized during genesis with a `MiningInterval` value less than 5 milliseconds.

**Attacker Capabilities:**
This is not a runtime attack - it requires control over genesis configuration. The attacker would need to either:
1. Be a malicious chain operator during genesis block creation
2. Exploit a misconfiguration in the deployment process

**Feasibility:**
The code path is executable and deterministic. Once initialized with a small mining interval:
- The value is permanently stored and reused for all subsequent terms: [8](#0-7) 
- No mechanism exists to update it post-genesis
- Term transitions will consistently fail

**Probability Reasoning:**
In practice, the likelihood is LOW because:
- All test configurations use 4000ms (4 seconds): [9](#0-8) 
- Single-miner scenarios default to 4000ms: [10](#0-9) 
- Genesis configuration is typically controlled by trusted operators

However, the lack of any validation makes accidental misconfiguration or malicious exploitation theoretically possible.

### Recommendation

**1. Add Minimum Value Validation in ConsensusOptions:**

Add a minimum value constant and validation in the consensus initialization to ensure `MiningInterval` is always at least 5 milliseconds (recommended: minimum 1000ms for practical block production):

```csharp
public class ConsensusOptions
{
    private const int MinimumMiningInterval = 1000; // 1 second minimum
    private int _miningInterval;
    
    public int MiningInterval 
    { 
        get => _miningInterval;
        set
        {
            if (value < MinimumMiningInterval)
                throw new ArgumentException($"MiningInterval must be at least {MinimumMiningInterval}ms");
            _miningInterval = value;
        }
    }
}
```

**2. Add Validation in FirstRound Method:**

Add an assertion in the `FirstRound` method:

```csharp
public override Empty FirstRound(Round input)
{
    Assert(State.CurrentRoundNumber.Value == 0, "Already initialized.");
    
    var miningInterval = input.GetMiningInterval();
    Assert(miningInterval >= 5, "MiningInterval must be at least 5ms to prevent zero mining limits");
    
    State.MiningInterval.Value = miningInterval;
    // ... rest of initialization
}
```

**3. Enhance CheckRoundTimeSlots Validation:**

Update the validation to check for minimum practical values:

```csharp
if (baseMiningInterval <= 0)
    return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

if (baseMiningInterval < 5)
    return new ValidationResult { Message = $"Mining interval must be at least 5ms to prevent zero mining limits.\n{this}" };
```

**4. Add Test Cases:**

Create regression tests that verify:
- Genesis initialization rejects MiningInterval < 5
- Round validation rejects rounds with intervals < 5
- The calculation produces non-zero mining limits for all valid intervals

### Proof of Concept

**Initial State:**
- Configure a new blockchain with genesis `ConsensusOptions.MiningInterval = 3` (3 milliseconds)
- Initialize with multiple miners to trigger the interval calculation path

**Execution Steps:**

1. **Genesis Initialization:**
   - Call `InitialAElfConsensusContract` with period configuration
   - Call `FirstRound` with a Round object where first two miners have expected mining times 3ms apart
   - Result: `State.MiningInterval.Value = 3`

2. **Wait for First Term Transition:**
   - Allow normal blocks to be produced during the initial term
   - When term period expires and term transition is required

3. **Term Transition Attempt:**
   - Miner produces block with `AElfConsensusBehaviour.NextTerm`
   - `TerminateRoundCommandStrategy.GetAEDPoSConsensusCommand()` is called
   - `LastBlockOfCurrentTermMiningLimit = 3 * 3 / 5 = 1` (or 0 for MiningInterval=1)
   - Consensus command sets `LimitMillisecondsOfMiningBlock = 1`

4. **Mining Validation Failure:**
   - `MiningRequestService.ValidateBlockMiningTime()` calculates:
     - `blockExecutionDuration = blockTime + 1ms - currentTime`
     - This is likely negative or nearly zero by validation time
   - Validation fails at the timeout check
   - `RequestMiningAsync` returns `null`

5. **Chain Halt:**
   - Term transition block is never produced
   - Consensus repeatedly retries but always fails the same validation
   - Chain cannot advance past the term boundary

**Expected vs Actual Result:**
- **Expected:** Term transition block is produced with sufficient mining time
- **Actual:** Mining validation consistently fails, no block is produced, chain halts at term boundary

**Success Condition:**
The chain is unable to produce any blocks after reaching the term transition point, demonstrating a complete denial of service caused by the zero/near-zero mining limit.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L60-60)
```csharp
        protected int LastBlockOfCurrentTermMiningLimit => MiningInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L36-37)
```csharp
                LimitMillisecondsOfMiningBlock =
                    _isNewTerm ? LastBlockOfCurrentTermMiningLimit : DefaultBlockMiningLimit
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L83-83)
```csharp
        State.MiningInterval.Value = input.GetMiningInterval();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L46-47)
```csharp
        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L72-74)
```csharp
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L10-10)
```csharp
    public int MiningInterval { get; set; }
```

**File:** src/AElf.Kernel/Miner/Application/IMiningRequestService.cs (L36-36)
```csharp
            return null;
```

**File:** src/AElf.Kernel/Miner/Application/IMiningRequestService.cs (L47-64)
```csharp
    private bool ValidateBlockMiningTime(Timestamp blockTime, Timestamp miningDueTime,
        Duration blockExecutionDuration)
    {
        if (miningDueTime - Duration.FromTimeSpan(TimeSpan.FromMilliseconds(250)) <
            blockTime + blockExecutionDuration)
        {
            Logger.LogDebug(
                "Mining canceled because mining time slot expired. MiningDueTime: {MiningDueTime}, BlockTime: {BlockTime}, Duration: {BlockExecutionDuration}",
                miningDueTime, blockTime, blockExecutionDuration);
            return false;
        }

        if (blockTime + blockExecutionDuration >= TimestampHelper.GetUtcNow()) return true;
        Logger.LogDebug(
            "Will cancel mining due to timeout: Actual mining time: {BlockTime}, execution limit: {BlockExecutionDuration} ms",
            blockTime, blockExecutionDuration.Milliseconds());
        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L240-240)
```csharp
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
```

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/AEDPoSContractTestConstants.cs (L15-15)
```csharp
    internal const int MiningInterval = 4000;
```
