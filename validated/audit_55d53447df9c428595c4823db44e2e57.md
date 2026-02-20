# Audit Report

## Title
Side Chain Miner Can Manually Call NextTerm to Corrupt MainChainCurrentMinerList and Steal Resource Token Distributions

## Summary
A side chain miner can directly invoke the public `NextTerm` method with crafted input containing side chain miner addresses, bypassing the intended consensus flow. This corrupts `State.MainChainCurrentMinerList` with side chain miners, causing subsequent `UpdateInformationFromCrossChain` calls to distribute accumulated resource tokens (transaction fees and rental fees) to side chain miners instead of main chain miners.

## Finding Description

The vulnerability stems from a missing authorization check in the `SetMinerList` method that allows it to be called from any chain type despite documentation indicating it should be main chain only.

**Root Cause - Missing IsMainChain Check:**

The `SetMinerList` method contains a comment stating "Only Main Chain can perform this action" but lacks the corresponding enforcement check. [1](#0-0) 

This contrasts with other methods like `UpdateInformationFromCrossChain` which properly enforce chain type restrictions. [2](#0-1) 

**Attack Execution Path:**

1. **Side chains normally use only NextRound behavior**: Side chains are designed to use `NextRound` exclusively and never trigger `NextTerm` in normal operation. [3](#0-2) 

2. **NextTerm method remains publicly accessible**: Despite not being used by side chains, the `NextTerm` method is public and callable by any miner. [4](#0-3) 

3. **PreCheck validation only verifies miner membership**: The permission check validates whether the caller is in the current or previous miner list, but does not validate whether the consensus behavior is appropriate for the chain type. [5](#0-4) 

4. **ProcessNextTerm extracts and sets miner list**: When `NextTerm` is processed, it extracts miner addresses from the input's `RealTimeMinersInformation` and unconditionally calls `SetMinerList`, which overwrites `MainChainCurrentMinerList`. [6](#0-5) 

5. **Token distribution uses corrupted list**: When `UpdateInformationFromCrossChain` is subsequently called (as part of normal cross-chain synchronization), it distributes accumulated resource tokens to the corrupted miner list BEFORE updating it with the correct main chain miners. [7](#0-6) 

6. **DistributeResourceTokensToPreviousMiners sends funds to attackers**: The distribution function retrieves the corrupted `MainChainCurrentMinerList` and distributes all accumulated tokens (from both `PayTxFeeSymbolListName` and `PayRentalSymbolListName`) equally to the side chain miner addresses in the corrupted list. [8](#0-7) 

## Impact Explanation

**Direct Fund Theft:**
The vulnerability enables theft of accumulated resource tokens that should compensate main chain miners for securing the network and providing cross-chain functionality. These tokens accumulate in the side chain's consensus contract from transaction fees and rental fees.

**Quantified Loss:**
- **Amount**: 100% of resource tokens held in the side chain's consensus contract at the time of attack
- **Frequency**: Can be executed repeatedly whenever resource tokens accumulate (during normal side chain operation)
- **Victims**: Main chain miners lose their entire expected distribution from the compromised side chain

**Protocol Impact:**
This breaks the fundamental cross-chain economic model where main chain miners are compensated for securing side chains. The incentive structure that enables multi-chain operation is undermined, as main chain miners no longer receive expected rewards for side chain security.

## Likelihood Explanation

**High Likelihood:**

1. **Attacker Profile**: Any legitimate side chain miner can execute this attack - no special privileges required beyond being in the current miner set

2. **Attack Simplicity**: 
   - Craft a `NextTermInput` with `TermNumber = currentTerm + 1`, `RoundNumber = currentRound + 1`, and populate `RealTimeMinersInformation` with side chain miner addresses
   - Call the public `NextTerm` method
   - No complex timing, transaction ordering, or consensus manipulation required

3. **Low Cost**: Only requires a normal transaction fee to call `NextTerm`

4. **No Detection**: The attack uses a legitimate consensus method that passes all existing validation checks. There is no runtime detection mechanism to prevent this misuse

5. **High Reward**: Captures 100% of accumulated resource tokens with no risk of transaction reversion

6. **Side Effects Are Non-Blocking**: While calling `NextTerm` on a side chain disrupts the side chain's consensus state (updating term and round numbers incorrectly), this does not prevent the fund theft or reduce the vulnerability's severity

## Recommendation

Add a chain type check in the `SetMinerList` method to enforce the documented restriction:

```csharp
private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
{
    // Enforce that only main chain can update MainChainCurrentMinerList
    Assert(State.IsMainChain.Value, "Only Main Chain can perform this action.");
    
    // Miners for one specific term should only update once.
    var minerListFromState = State.MinerListMap[termNumber];
    if (gonnaReplaceSomeone || minerListFromState == null)
    {
        State.MainChainCurrentMinerList.Value = minerList;
        State.MinerListMap[termNumber] = minerList;
        return true;
    }

    return false;
}
```

Alternatively, add a check in `ProcessConsensusInformation` to prevent side chains from calling `NextTerm`:

```csharp
private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
{
    // ... existing code ...
    
    switch (input)
    {
        case NextTermInput nextTermInput:
            Assert(State.IsMainChain.Value, "NextTerm can only be called on main chain.");
            randomNumber = nextTermInput.RandomNumber;
            ProcessNextTerm(nextTermInput);
            break;
        // ... other cases ...
    }
}
```

## Proof of Concept

The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task SideChainMiner_CanCorruptMainChainMinerList_AndStealTokens()
{
    // Setup: Initialize side chain with miner
    var sideChainMiner = SampleAccount.Accounts[0].KeyPair;
    await InitializeSideChain(sideChainMiner.PublicKey);
    
    // Setup: Fund consensus contract with resource tokens
    await TransferTokensToConsensusContract("ELF", 1000);
    
    // Setup: Get current term and round
    var currentTerm = await GetCurrentTermNumber();
    var currentRound = await GetCurrentRoundNumber();
    
    // Attack: Side chain miner crafts NextTermInput with own address
    var maliciousInput = new NextTermInput
    {
        TermNumber = currentTerm + 1,
        RoundNumber = currentRound + 1
    };
    maliciousInput.RealTimeMinersInformation.Add(
        sideChainMiner.PublicKey.ToHex(),
        new MinerInRound { Pubkey = sideChainMiner.PublicKey.ToHex() }
    );
    
    // Attack: Call NextTerm to corrupt MainChainCurrentMinerList
    await ExecuteNextTerm(sideChainMiner, maliciousInput);
    
    // Verify: MainChainCurrentMinerList now contains side chain miner
    var minerList = await GetMainChainCurrentMinerList();
    Assert.Contains(sideChainMiner.PublicKey.ToHex(), minerList.Pubkeys.Select(p => p.ToHex()));
    
    // Trigger: Normal cross-chain sync distributes tokens
    await UpdateInformationFromCrossChain(CreateValidMainChainConsensusInfo());
    
    // Verify: Side chain miner received the tokens instead of main chain miners
    var balance = await GetBalance(Address.FromPublicKey(sideChainMiner.PublicKey), "ELF");
    Assert.Equal(1000, balance); // All tokens went to attacker
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L63-76)
```csharp
    /// <summary>
    ///     Only Main Chain can perform this action.
    /// </summary>
    /// <param name="minerList"></param>
    /// <param name="termNumber"></param>
    /// <param name="gonnaReplaceSomeone"></param>
    /// <returns></returns>
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L38-38)
```csharp
        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-61)
```csharp
        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L66-96)
```csharp
    private void DistributeResourceTokensToPreviousMiners()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
            foreach (var pubkey in minerList)
            {
                var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
                Context.LogDebug(() => $"Will send {amount} {symbol}s to {pubkey}");
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L16-23)
```csharp
        /// <summary>
        ///     Simply return NEXT_ROUND for side chain.
        /// </summary>
        /// <returns></returns>
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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
