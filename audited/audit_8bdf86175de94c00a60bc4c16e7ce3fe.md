# Audit Report

## Title
Front-Running Vulnerability in NFT Symbol Generation via Predictable Randomness

## Summary
The NFT contract's symbol generation mechanism uses predictable on-chain data, allowing attackers to calculate symbol numbers before victim transactions execute and front-run to claim desirable symbols. This completely breaks the fairness guarantee of random symbol allocation.

## Finding Description

The vulnerability exists in the symbol generation process for NFT protocol creation. When a user calls the public `Create()` method [1](#0-0) , it invokes `GetSymbol()` which generates a symbol number using `GenerateSymbolNumber()` [2](#0-1) .

The critical flaw is in how `GenerateSymbolNumber()` obtains randomness. It retrieves random bytes from the consensus contract using the previous block's height [3](#0-2) . The consensus contract's `GetRandomBytes()` method simply returns stored random hashes [4](#0-3) , which retrieves `State.RandomHashes[height]` [5](#0-4) .

These random hashes are stored during block production [6](#0-5) . When a transaction executes in block N+1, it reads `State.RandomHashes[N]` which is already finalized and publicly accessible.

**Attack Sequence:**
1. Victim submits `Create()` transaction to mempool (for inclusion in block N+1)
2. Attacker monitors mempool and extracts victim's address from pending transaction
3. Attacker reads `State.RandomHashes[N]` from current on-chain state (already public)
4. Attacker calculates: `randomHash = HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(victimAddress), HashHelper.ComputeFrom(randomBytes))`
5. Attacker calculates: `symbolNumber = Context.ConvertHashToInt64(randomHash, from, from*10)`
6. If symbol number is desirable (e.g., low number, specific pattern), attacker submits own transaction with higher gas
7. Attacker's transaction executes first, claiming the symbol via `State.IsCreatedMap[randomNumber] = true` [7](#0-6) 
8. Victim's transaction executes and gets a different (less desirable) symbol

The do-while loop check [8](#0-7)  only prevents duplicate numbers but provides no protection against front-running, as attackers can calculate unused numbers before submitting.

## Impact Explanation

This vulnerability has **HIGH** severity impact:

**Protocol Fairness Compromise:** The NFT protocol's core assumption of fair, random symbol allocation is completely broken. Symbol numbers starting at 9 digits [9](#0-8)  determine protocol identity and branding.

**Economic Exploitation:** Certain symbols have inherent value similar to vanity addresses or premium domain names (e.g., sequential numbers, low numbers, patterns like "111111111"). Attackers can systematically claim all valuable symbols and potentially resell them or extract value through squatting.

**User Experience Degradation:** Legitimate users lose the ability to obtain fair random symbol assignments, fundamentally undermining trust in the NFT creation process.

**Systematic Nature:** This is not a one-time exploit but enables ongoing, systematic exploitation with minimal cost (only transaction fees). The attack has near 100% success rate with sufficient gas price premium.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of exploitation:

**Attacker Capabilities:** Only standard blockchain capabilities required:
- Mempool monitoring - publicly available
- On-chain state reading - public RPC methods
- Hash calculations - trivial off-chain computation
- Transaction submission with priority - standard transaction mechanism

**Attack Complexity:** Low - attackers need only implement mempool monitoring, replicate the symbol generation logic, and submit prioritized transactions.

**Preconditions:** Realistic - only requires pending `Create()` transactions in mempool, which occurs during normal protocol operation.

**Economic Incentive:** High - valuable symbols can be claimed with minimal cost (transaction fees), creating strong incentive for exploitation.

**Detection Difficulty:** Attacks appear as legitimate NFT creation transactions, making them difficult to distinguish from normal usage.

## Recommendation

Implement a commit-reveal scheme or use future block randomness:

**Option 1: Commit-Reveal Scheme**
- User commits to creating NFT in transaction 1 (stores hash of secret + address)
- After commitment is confirmed, user reveals secret in transaction 2
- Symbol generated using revealed secret + future block hash (unknown at commit time)

**Option 2: Future Block Randomness**
- Generate symbol using `Context.CurrentHeight + N` (future block)
- Require two-step process: initiate creation, then finalize after N blocks
- Ensures randomness source is unknown when transaction is submitted

**Option 3: Alternative Randomness Source**
- Use transaction-specific randomness like `HashHelper.ConcatAndCompute(Context.TransactionId, Context.PreviousBlockHash, Context.Sender)`
- This makes front-running impractical as TransactionId is only known after transaction is created

## Proof of Concept

```csharp
// Attacker's off-chain code (pseudocode):
public string PredictSymbol(Address victimAddress, long currentHeight) {
    // Read from chain
    var randomBytes = ConsensusContract.GetRandomBytes(currentHeight); 
    var nftTypeShortName = "AR"; // Or extracted from pending transaction
    
    // Replicate GenerateSymbolNumber logic
    var randomHash = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(victimAddress),
        HashHelper.ComputeFrom(randomBytes)
    );
    
    var length = 9; // NumberMinLength
    var from = 100000000L; // 10^8
    var randomNumber = ConvertHashToInt64(randomHash, from, from * 10);
    
    // Check if desirable (e.g., low number, pattern)
    if (IsDesirable(randomNumber)) {
        // Submit own Create() transaction with higher gas
        SubmitCreateTransaction(nftTypeShortName, higherGasPrice);
    }
    
    return $"{nftTypeShortName}{randomNumber}";
}
```

The attacker monitors mempool, runs this calculation for each pending Create() transaction, and front-runs when a desirable symbol is detected.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-20)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-27)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-77)
```csharp
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L79-82)
```csharp
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L117-122)
```csharp
    public override Hash GetRandomHash(Int64Value input)
    {
        Assert(input.Value > 1, "Invalid block height.");
        Assert(Context.CurrentHeight >= input.Value, "Block height not reached.");
        return State.RandomHashes[input.Value] ?? Hash.Empty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L124-129)
```csharp
    public override BytesValue GetRandomBytes(BytesValue input)
    {
        var height = new Int64Value();
        height.MergeFrom(input.Value);
        return GetRandomHash(height).ToBytesValue();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```
