# Audit Report

## Title
Missing LIB Validation in NextRound/NextTerm Allows Arbitrary Irreversible Block Height Manipulation

## Summary
The AEDPoS consensus contract fails to validate Last Irreversible Block (LIB) values during NextRound and NextTerm transitions. The `LibInformationValidationProvider` is only applied to UpdateValue behavior, allowing malicious miners to submit arbitrary LIB values that corrupt blockchain health monitoring and cause persistent state corruption.

## Finding Description

The validation architecture conditionally applies validators based on consensus behavior. For UpdateValue, the `LibInformationValidationProvider` is correctly added to the validation pipeline to prevent LIB values from going backward [1](#0-0) . However, for NextRound and NextTerm behaviors, this critical validator is absent [2](#0-1) .

The `LibInformationValidationProvider` contains logic to validate that provided LIB values don't decrease compared to the base round [3](#0-2) , but this validation is never applied to NextRound/NextTerm behaviors.

During NextRound processing, the input is directly converted to a Round object [4](#0-3)  via `ToRound()`, which blindly copies the `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields without any validation [5](#0-4) . This converted Round is then stored directly into state [6](#0-5) .

The honest code path correctly generates NextRound data that preserves LIB values from the current round [7](#0-6) . However, since `NextRound` is a public method accepting `NextRoundInput` as a parameter [8](#0-7) , there is no enforcement that the submitted data matches honestly generated values. A malicious miner can modify the LIB fields before submission, and the contract will accept them without validation.

## Impact Explanation

**Blockchain Health Monitoring Corruption**: The `GetMaximumBlocksCount` function reads the stored `ConfirmedIrreversibleBlockRoundNumber` and `ConfirmedIrreversibleBlockHeight` to assess blockchain health status (Normal/Abnormal/Severe) [9](#0-8) . A malicious miner could inflate these values to falsely indicate "Normal" status when the chain is actually experiencing severe fork conditions. This prevents the protocol from triggering defensive measures like reducing the maximum blocks count or firing `IrreversibleBlockHeightUnacceptable` events.

**State Corruption Persistence**: Once corrupted LIB values are injected, they persist and affect subsequent UpdateValue operations. The LIB update logic during UpdateValue only allows increases, never decreases [10](#0-9) . If a malicious miner sets `ConfirmedIrreversibleBlockHeight` to an artificially high value (e.g., 1 million), subsequent honest UpdateValue calculations cannot correct this, permanently corrupting the consensus state.

**Impact Severity**: High - breaks blockchain health monitoring guarantees, causes irreversible state corruption, and could mask critical consensus issues.

## Likelihood Explanation

**Attacker Profile**: Any miner in the validator set can execute this attack when they become the extra block producer for a round. In AEDPoS, this role rotates among miners, ensuring all validators eventually obtain this capability.

**Attack Complexity**: Low. The attack requires:
1. Wait for designation as extra block producer (happens naturally through rotation)
2. Generate honest consensus data via off-chain node software
3. Modify `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields in NextRoundInput
4. Submit the modified NextRound transaction

**Detection Difficulty**: Initial detection is difficult as the contract accepts the values without validation. Discrepancies would only emerge through external monitoring or when GetMaximumBlocksCount calculations produce inconsistent results.

**Likelihood**: Medium - requires a compromised or malicious miner but the attack is straightforward once the opportunity arises.

## Recommendation

Add `LibInformationValidationProvider` to the validation pipeline for NextRound and NextTerm behaviors. The fix should be applied in the `ValidateBeforeExecution` method:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this
    break;
```

This ensures that LIB values in NextRound and NextTerm submissions are validated against the current round's LIB values, preventing backward movement or arbitrary inflation.

## Proof of Concept

```csharp
// POC: Malicious miner submits NextRound with inflated LIB values
[Fact]
public async Task MaliciousMinerCanInflateLIBValues()
{
    // Setup: Initialize consensus with normal round
    var currentRound = await GetCurrentRoundInformation();
    var currentLIB = currentRound.ConfirmedIrreversibleBlockHeight; // e.g., 100
    
    // Attack: Malicious miner generates NextRound with inflated LIB
    var nextRoundInput = GenerateNextRoundInput(currentRound);
    nextRoundInput.ConfirmedIrreversibleBlockHeight = 1000000; // Inflated value
    nextRoundInput.ConfirmedIrreversibleBlockRoundNumber = 1000;
    
    // Execute: Submit malicious NextRound transaction
    var result = await AEDPoSContractStub.NextRound.SendAsync(nextRoundInput);
    
    // Verify: The inflated LIB values are stored without validation
    var newRound = await GetCurrentRoundInformation();
    Assert.Equal(1000000, newRound.ConfirmedIrreversibleBlockHeight); // Attack succeeded
    
    // Impact: GetMaximumBlocksCount now returns incorrect health status
    var maxBlocksCount = await AEDPoSContractStub.GetMaximumBlocksCount.CallAsync(new Empty());
    Assert.Equal(8, maxBlocksCount.Value); // Should be 1 (Severe status) but shows Normal
}
```

## Notes

The cross-chain impact mentioned in the original claim is less directly verifiable from the consensus contract code alone. While consensus extra data (which includes LIB values) is propagated to side chains via ACS11, the specific usage of `ConfirmedIrreversibleBlockHeight` for cross-chain indexing decisions requires further investigation of the cross-chain contract implementation. However, the confirmed impacts on blockchain health monitoring and state corruption are sufficient to establish this as a high-severity vulnerability.

The same issue affects NextTerm behavior [11](#0-10) , which also blindly copies LIB fields without validation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-91)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-280)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-39)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```
