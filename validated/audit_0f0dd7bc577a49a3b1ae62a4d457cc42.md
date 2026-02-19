# Audit Report

## Title
Missing LIB Upper Bound Validation in NextRound/NextTerm Enables Consensus DOS via Integer Overflow

## Summary
The consensus validation architecture fails to validate Last Irreversible Block (LIB) values for `NextRound` and `NextTerm` behaviors, allowing a malicious miner to inject extreme `ConfirmedIrreversibleBlockHeight` values that bypass validation but eventually trigger arithmetic overflow in `GetMaximumBlocksCount()`, permanently halting blockchain consensus.

## Finding Description

The AEDPoS consensus contract employs behavior-specific validation providers that are selectively applied based on consensus behavior type. A critical validation gap exists where `LibInformationValidationProvider` is only registered for `UpdateValue` behavior but not for `NextRound` or `NextTerm` behaviors. [1](#0-0) 

The `LibInformationValidationProvider` validates that LIB values do not move backward, checking both `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber`: [2](#0-1) 

However, `NextRound` and `NextTerm` behaviors only use `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`, neither of which validate LIB bounds: [3](#0-2) 

This allows a malicious miner to inject arbitrary `ConfirmedIrreversibleBlockHeight` values in `NextRoundInput` or `NextTermInput`: [4](#0-3) 

The malicious round is stored directly to state via `AddRoundInformation`: [5](#0-4) 

The post-execution hash validation also fails to detect this because `GetCheckableRound()` explicitly excludes LIB fields from the hash computation: [6](#0-5) 

Once stored, the malicious LIB value causes arithmetic overflow in `GetMaximumBlocksCount()`, which is invoked on every consensus transaction. When the blockchain enters Severe mining status, the method attempts to compute the distance from current height to the malicious LIB height using SafeMath's checked arithmetic: [7](#0-6) 

The `Sub()` method uses C#'s `checked` keyword, throwing `OverflowException` on underflow: [8](#0-7) 

**Attack Execution:**
1. Malicious miner waits for NextRound/NextTerm slot
2. Modifies consensus data to inject `ConfirmedIrreversibleBlockHeight = long.MaxValue`
3. Sets `ConfirmedIrreversibleBlockRoundNumber` to avoid immediate Severe status (e.g., currentRound - 1)
4. Block passes validation and malicious round is stored
5. After sufficient rounds, blockchain enters Severe status due to stalled LIB
6. `GetMaximumBlocksCount()` attempts `currentHeight.Sub(long.MaxValue)`, causing `OverflowException`
7. All subsequent blocks fail permanently

## Impact Explanation

**Severity: Critical** - Complete consensus halt with no automatic recovery mechanism.

Once the malicious LIB value enters state and triggers the overflow, the blockchain cannot produce any new blocks. The `GetMaximumBlocksCount()` method is called during `ProcessConsensusInformation`, which is invoked for every consensus transaction: [9](#0-8) 

This creates a permanent DOS condition where:
- No blocks can be produced by any miner
- The blockchain state is frozen at the point of attack
- Recovery requires hard fork or state rollback to before the malicious round

The attack affects the entire blockchain network, not just individual users, making this a protocol-level availability failure.

## Likelihood Explanation

**Likelihood: Medium-High** given miner access.

**Prerequisites:**
- Attacker must be an active miner in the current miner list
- For mainchain: requires being elected through the election contract (high barrier but achievable)
- For sidechains: requires being in the configured miner set (potentially lower barrier)

**Attack Feasibility:**
- Once miner status is achieved, attack complexity is LOW
- No special transaction crafting required - simply modify Round object before block production
- Single malicious block sufficient to poison consensus state
- No runtime detection until overflow triggers

**Economic Factors:**
- Honest miners have incentive to maintain chain health
- However, compromised miners, exiting miners, or Byzantine actors can execute this attack
- Single malicious miner suffices - no coordination required

**Exploitability: High** - The validation gap is architectural and cannot be prevented by individual node operators.

## Recommendation

Add `LibInformationValidationProvider` to the validation provider list for `NextRound` and `NextTerm` behaviors in `AEDPoSContract_Validation.cs`:

```csharp
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
}
```

Additionally, consider adding upper bound validation in `LibInformationValidationProvider` to reject unreasonably large LIB values that could never be reached in practice (e.g., values beyond a reasonable multiple of current height).

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousLIBValueCausesConsensusHalt()
{
    // Setup: Get to a state where NextRound can be triggered
    var consensusContract = GetAEDPoSContract();
    var maliciousMiner = SampleAccount.Accounts[0];
    
    // Attacker produces NextRound block with malicious LIB
    var currentRound = await consensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    var maliciousRound = GenerateNextRound(currentRound);
    
    // Inject malicious values
    maliciousRound.ConfirmedIrreversibleBlockHeight = long.MaxValue;
    maliciousRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber - 1; // Avoid immediate Severe status
    
    // Create malicious NextRoundInput
    var maliciousInput = NextRoundInput.Create(maliciousRound, GenerateRandomNumber());
    
    // Execute NextRound - should pass validation due to missing LibInformationValidationProvider
    var result = await consensusContract.NextRound.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Advance rounds until Severe status is triggered
    for (int i = 0; i < 10; i++)
    {
        await ProduceNormalBlock(consensusContract);
    }
    
    // Next block should fail with OverflowException in GetMaximumBlocksCount
    var exception = await Assert.ThrowsAsync<OverflowException>(async () =>
    {
        await ProduceNormalBlock(consensusContract);
    });
    
    // Consensus is now permanently halted
    exception.ShouldNotBeNull();
}
```

**Notes:**
This vulnerability represents a fundamental architectural flaw in the consensus validation design where behavior-specific validation is incomplete. The attack is realistic for any actor who can achieve miner status, and the impact is catastrophic (permanent chain halt). The fix is straightforward but requires protocol upgrade.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-106)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
```
