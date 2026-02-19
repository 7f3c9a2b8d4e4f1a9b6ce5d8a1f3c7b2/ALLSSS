# Audit Report

## Title
Cross-Chain Consensus Update DoS via Unbounded Round Number Injection

## Summary
The `UpdateInformationFromCrossChain` function in the AEDPoS consensus contract lacks upper bound validation on incoming round numbers from cross-chain updates. This allows injection of extremely large round number values (e.g., `long.MaxValue`) that permanently block all subsequent legitimate consensus updates, creating a denial-of-service condition for cross-chain consensus synchronization on side chains.

## Finding Description

The vulnerability stems from a validation inconsistency between normal consensus round transitions and cross-chain consensus updates.

**Normal Consensus Path** enforces strict round number validation where rounds must increment by exactly 1: [1](#0-0) [2](#0-1) 

**Cross-Chain Update Path** only validates that the incoming round number is strictly greater than the stored value, with no upper bound: [3](#0-2) 

If an attacker supplies `RoundNumber = long.MaxValue`, it passes this check and updates the state: [4](#0-3) 

**Why Protections Fail:**

The CrossChain contract's `ValidateParentChainBlockData` only validates structural properties (chain ID, height continuity, merkle root presence) but does not validate consensus round number values: [5](#0-4) 

The consensus information bytes are extracted from `ParentChainBlockData.ExtraData` and passed directly to the consensus contract without semantic validation: [6](#0-5) [7](#0-6) 

**Execution Path:**

1. Current miner calls `ProposeCrossChainIndexing` with crafted `ParentChainBlockData` containing malicious consensus info with `RoundNumber = long.MaxValue` in ExtraData
2. `ValidateParentChainBlockData` validates only structural properties, not consensus values
3. Parliament proposal created with only chain ID as params (not the actual consensus data values): [8](#0-7) 

4. Parliament approves proposal based on chain ID, unaware of malicious round number in stored data
5. `ReleaseCrossChainIndexingProposal` → `RecordCrossChainData` → `IndexParentChainBlockData` → `UpdateConsensusInformation` → `UpdateInformationFromCrossChain`
6. Malicious round number accepted and stored
7. All future legitimate updates are rejected because any normal round number ≤ injected value

## Impact Explanation

**Direct Harm:** Complete denial-of-service of cross-chain consensus information updates for the affected side chain. Once `State.MainChainRoundNumber.Value` is set to an extremely large value like `long.MaxValue`, the side chain can no longer receive:
- Updated miner lists from the main chain
- Updated consensus round information  
- Critical cross-chain coordination data

**Protocol Damage:** The side chain's cross-chain consensus mechanism becomes permanently stuck. This affects:
- Cross-chain miner list synchronization (stored at line 55-61 of `AEDPoSContract_ACS11_CrossChainInformationProvider.cs`)
- Resource token distribution to miners which depends on the updated miner list: [9](#0-8) 

- Cross-chain operation integrity and coordination

**Who Is Affected:** All participants in the side chain ecosystem, as the chain can no longer maintain consensus synchronization with its parent chain.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a current miner to propose cross-chain indexing data (enforced at line 286): [10](#0-9) 

- Requires parliament approval (majority miner vote) to accept the proposal

**Attack Complexity:** Moderate - The key issue is that the validation gap creates a mis-scoped privilege scenario. The parliament is trusted but the system does not provide adequate information for proper validation:
- The proposal parameters only contain the chain ID, not the actual consensus data values
- Miners voting on proposals must verify the consensus data off-chain
- Without proper off-chain verification tooling, malicious data could pass through governance
- No on-chain constraints prevent acceptance of unreasonable round number values

**Feasibility Conditions:**
- Side chain with cross-chain indexing enabled
- Current miner with proposal rights
- Either: (a) majority miner collusion, or (b) insufficient off-chain validation by parliament members

**Detection Constraints:** The attack is visible on-chain as an abnormal round number jump, but prevention requires active monitoring and off-chain verification of proposed consensus values before parliament approval.

## Recommendation

Add upper bound validation to the cross-chain consensus update path. The fix should enforce that the incoming round number can only increment by a reasonable amount (e.g., 1 or a small bounded range) similar to the normal consensus path:

```csharp
public override Empty UpdateInformationFromCrossChain(BytesValue input)
{
    Assert(
        Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
        "Only Cross Chain Contract can call this method.");

    Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

    if (input == null || input.Value.IsEmpty) return new Empty();

    var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

    // Check round number is greater than current
    if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
        return new Empty();
    
    // ADD: Enforce bounded increment (e.g., maximum 1 or small reasonable range)
    var currentRoundNumber = State.MainChainRoundNumber.Value;
    if (currentRoundNumber > 0 && 
        consensusInformation.Round.RoundNumber > currentRoundNumber + 1)
    {
        Assert(false, "Round number increment too large for cross-chain update.");
    }

    // ... rest of function
}
```

Alternatively, validate the consensus round number reasonableness in `ValidateParentChainBlockData` before the proposal is created, ensuring parliament votes on validated data only.

## Proof of Concept

```csharp
[Fact]
public async Task UpdateInformationFromCrossChain_UnboundedRoundNumber_DoS()
{
    SetToSideChain();
    InitialContracts();
    
    var mockedCrossChain = SampleAccount.Accounts.Last();
    var mockedCrossChainStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
        mockedCrossChain.KeyPair);

    // Step 1: Inject extremely large round number
    var maliciousHeaderInformation = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = long.MaxValue, // Malicious injection
            RealTimeMinersInformation = {
                { Accounts[0].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };

    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
    {
        Value = maliciousHeaderInformation.ToByteString()
    });

    // Step 2: Verify malicious round number was stored
    var mainChainRoundNumber = await ConsensusStub.GetMainChainRoundNumber.CallAsync(new Empty());
    mainChainRoundNumber.Value.ShouldBe(long.MaxValue);

    // Step 3: Attempt legitimate update - it will be rejected
    var legitimateHeaderInformation = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 2, // Normal legitimate round number
            RealTimeMinersInformation = {
                { Accounts[1].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };

    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
    {
        Value = legitimateHeaderInformation.ToByteString()
    });

    // Step 4: Verify the legitimate update was rejected (round number unchanged)
    var finalRoundNumber = await ConsensusStub.GetMainChainRoundNumber.CallAsync(new Empty());
    finalRoundNumber.Value.ShouldBe(long.MaxValue); // Still the malicious value
    
    // DoS confirmed: side chain can no longer receive consensus updates
}
```

**Notes**

This vulnerability represents a critical validation gap where the cross-chain update path lacks the strict round number increment validation enforced in normal consensus operations. The issue is about mis-scoped privileges - the parliament is trusted, but the system provides insufficient validation mechanisms to allow them to make informed decisions. The proposal parameters contain only the chain ID, not the consensus data values, requiring off-chain verification that may be insufficient or absent. This allows unreasonable round number values to be injected, permanently blocking legitimate cross-chain consensus synchronization on side chains.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L91-96)
```csharp
    private bool TryToUpdateRoundNumber(long roundNumber)
    {
        var oldRoundNumber = State.CurrentRoundNumber.Value;
        if (roundNumber != 1 && oldRoundNumber + 1 != roundNumber) return false;
        State.CurrentRoundNumber.Value = roundNumber;
        return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-30)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L46-47)
```csharp
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-53)
```csharp
        DistributeResourceTokensToPreviousMiners();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L55-55)
```csharp
        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L227-234)
```csharp
    private void UpdateConsensusInformation(ByteString bytes)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        Context.SendInline(State.CrossChainInteractionContract.Value,
            nameof(State.CrossChainInteractionContract.UpdateInformationFromCrossChain),
            new BytesValue { Value = bytes });
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L402-405)
```csharp
                    Params = new AcceptCrossChainIndexingProposalInput
                    {
                        ChainId = chainId
                    }.ToByteString(),
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L720-743)
```csharp
    private bool ValidateParentChainBlockData(IList<ParentChainBlockData> parentChainBlockData,
        out Dictionary<int, List<ParentChainBlockData>> validatedParentChainBlockData)
    {
        var parentChainId = State.ParentChainId.Value;
        var currentHeight = State.CurrentParentChainHeight.Value;
        validatedParentChainBlockData = new Dictionary<int, List<ParentChainBlockData>>();
        foreach (var blockData in parentChainBlockData)
        {
            if (parentChainId != blockData.ChainId || currentHeight + 1 != blockData.Height ||
                blockData.TransactionStatusMerkleTreeRoot == null)
                return false;
            if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
                    State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
                    State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
                return false;

            currentHeight += 1;
        }

        if (parentChainBlockData.Count > 0)
            validatedParentChainBlockData[parentChainId] = parentChainBlockData.ToList();

        return true;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L783-788)
```csharp
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
            }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L286-286)
```csharp
        AssertAddressIsCurrentMiner(Context.Sender);
```
