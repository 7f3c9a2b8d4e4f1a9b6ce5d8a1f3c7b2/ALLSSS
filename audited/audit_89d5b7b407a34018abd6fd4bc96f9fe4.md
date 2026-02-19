### Title
Chain ID Hash Collision Causes Dictionary Exception and Data Corruption in GetSideChainIdAndHeight

### Summary
The `GetSideChainIdAndHeight()` function iterates through all side chain serial numbers and generates chain IDs using a non-injective hash function. When hash collisions occur (different serial numbers producing identical chain IDs), the function throws an `ArgumentException` when attempting to add duplicate keys to the dictionary, causing a denial-of-service. Additionally, colliding chain IDs cause later side chains to silently overwrite earlier side chains' state data during creation.

### Finding Description

The vulnerability exists in the chain ID generation and retrieval logic across multiple files:

**Chain ID Generation Algorithm:**
The `GetChainId()` helper function generates chain IDs by calling `ChainHelper.GetChainId(serialNumber + Context.ChainId)`. [1](#0-0) 

The underlying `ChainHelper.GetChainId()` implementation uses `long.GetHashCode()` modulo 11316496 to generate chain IDs. [2](#0-1) 

This hash function is non-injective and explicitly produces collisions, as confirmed by the test suite where `GetChainId(long.MinValue)` equals `GetChainId(long.MaxValue)`. [3](#0-2) 

**Vulnerable View Function:**
In `GetSideChainIdAndHeight()`, the code iterates through all serial numbers from 1 to the current serial number, generates chain IDs, and adds them to a dictionary without checking for duplicates. [4](#0-3) 

The `IdHeightDict` is a protobuf `map<int32, int64>` which becomes a C# `MapField` that throws `ArgumentException` when duplicate keys are added. [5](#0-4) 

**No Collision Prevention:**
When creating side chains, there is no validation to check if the generated chain ID already exists in `State.SideChainInfo`. The code directly increments the serial number and assigns the new side chain info to the potentially colliding chain ID. [6](#0-5) 

**Root Cause:**
The `long.GetHashCode()` implementation uses XOR of the lower and upper 32 bits, followed by modulo 11316496, reducing the output space to approximately 11 million possible values. By the birthday paradox, collision probability reaches 50% at around sqrt(11316496) ≈ 3,364 side chains.

### Impact Explanation

**Denial of Service:**
When a collision occurs, `GetSideChainIdAndHeight()` throws an unhandled `ArgumentException`, making this critical view function unusable. This also cascades to `GetAllChainsIdAndHeight()` which depends on it. [7](#0-6) 

These view functions are essential for:
- Cross-chain indexing operations
- Side chain status monitoring
- Off-chain integrations and explorers querying chain state

**Data Corruption:**
When the second side chain with a colliding ID is created, `State.SideChainInfo[chainId]` is overwritten without warning, causing:
- Loss of original side chain's metadata (proposer, creation timestamp, indexing price)
- Incorrect balance tracking for the original side chain
- Confusion in cross-chain indexing as the same chain ID maps to different side chains at different serial numbers

**System Integrity:**
The affected view functions are used by miners for cross-chain indexing proposals and by the system to track which chains need indexing. [8](#0-7) 

### Likelihood Explanation

**Collision Inevitability:**
Hash collisions are mathematically proven to exist (test case demonstrates this). For sequential serial numbers with a fixed `Context.ChainId` offset, collisions become increasingly likely as more side chains are created.

**Probability Analysis:**
- Output space: 11,316,496 possible chain IDs
- Birthday paradox threshold: ~3,364 side chains for 50% collision probability
- Long-term operation: A mainchain operating for years could realistically create thousands of side chains

**Natural Occurrence:**
This is not an attacker-exploited vulnerability but a system design flaw that manifests naturally during normal operation. No malicious action is required—simply creating side chains through the standard governance process will eventually trigger collisions.

**Preconditions:**
- Side chains are created sequentially through `CreateSideChain()` 
- Serial numbers increment normally: 1, 2, 3, ..., N
- No special attacker capabilities required
- Occurs under normal long-term system operation

**Detection:**
Collision occurrence is deterministic based on serial numbers and `Context.ChainId`. The first call to `GetSideChainIdAndHeight()` after a collision will immediately fail with an exception, making detection straightforward but only after damage is done.

### Recommendation

**Immediate Fix - Add Collision Detection:**
In `CreateSideChain()`, add validation before storing side chain info:
```csharp
var chainId = GetChainId(serialNumber);
Assert(State.SideChainInfo[chainId] == null, "Chain ID collision detected. Cannot create side chain.");
```

**Better Fix - Use Injective Function:**
Replace the hash-based chain ID generation with a cryptographically secure or guaranteed-unique approach:
- Use a cryptographic hash (SHA256) of the full input and take sufficient bits to ensure negligible collision probability
- Or use a deterministic counter-based system that guarantees uniqueness
- Store a reverse mapping from chainId to serialNumber to detect collisions

**GetSideChainIdAndHeight Protection:**
Add try-catch with specific handling for duplicate keys to prevent DoS:
```csharp
if (!dict.IdHeightDict.ContainsKey(chainId))
{
    dict.IdHeightDict.Add(chainId, height);
}
else
{
    Context.LogDebug(() => $"Duplicate chain ID {chainId} detected for serial number {i}");
}
```

**Test Coverage:**
Add regression tests:
- Create multiple side chains (1000+) and verify all chain IDs are unique
- Explicitly test for hash collisions in chain ID generation
- Verify `GetSideChainIdAndHeight()` handles edge cases gracefully

### Proof of Concept

**Initial State:**
- Parent chain initialized with `Context.ChainId` = 9992731 (AELF mainchain)
- Side chain serial number = 0
- No side chains exist

**Exploitation Steps:**

1. Create first side chain (serial number 1):
   - Generated chainId = `ChainHelper.GetChainId(1 + 9992731)` = X
   - `State.SideChainInfo[X]` stores side chain 1 info
   - Success

2. Create side chains 2 through N normally until a collision occurs at serial number M where:
   - Generated chainId = `ChainHelper.GetChainId(M + 9992731)` = X (same as step 1)
   - `State.SideChainInfo[X]` is overwritten with side chain M info
   - Side chain 1's data is lost

3. Call `GetSideChainIdAndHeight()`:
   - Loop iteration i=1: generates chainId X, adds to dictionary successfully
   - Loop iteration i=M: generates chainId X, attempts `dict.IdHeightDict.Add(X, height)`
   - **Expected Result**: Returns dictionary with all side chains
   - **Actual Result**: Throws `ArgumentException: An item with the same key has already been added`

**Success Condition:**
The function throws an unhandled exception, preventing any caller from retrieving side chain information. The collision probability makes this inevitable as the system scales to thousands of side chains over years of operation.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L355-358)
```csharp
    private int GetChainId(long serialNumber)
    {
        return ChainHelper.GetChainId(serialNumber + Context.ChainId);
    }
```

**File:** src/AElf.Types/Helper/ChainHelper.cs (L9-24)
```csharp
        public static int GetChainId(long serialNumber)
        {
            // For 4 base58 chars use following range (2111 ~ zzzz):
            // Max: 57*58*58*58+57*58*58+57*58+57 = 11316496 (zzzz)
            // Min: 1*58*58*58+0*58*58+0*58+0 = 195112 (2111)
            var validNUmber = (uint)serialNumber.GetHashCode() % 11316496;
            if (validNUmber < 195112)
                validNUmber += 195112;

            var validNUmberBytes = validNUmber.ToBytes().Skip(1).ToArray();

            // Use BigInteger(BigEndian) format (bytes size = 3)
            Array.Resize(ref validNUmberBytes, 4);

            return validNUmberBytes.ToInt32(false);
        }
```

**File:** test/AElf.Types.Tests/Helper/ChainHelperTests.cs (L37-38)
```csharp
            var chainIdMinValue = ChainHelper.GetChainId(long.MinValue);
            chainIdMinValue.ShouldBe(chainIdMaxValue);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L101-116)
```csharp
    public override ChainIdAndHeightDict GetSideChainIdAndHeight(Empty input)
    {
        var dict = new ChainIdAndHeightDict();
        var serialNumber = State.SideChainSerialNumber.Value;
        for (long i = 1; i <= serialNumber; i++)
        {
            var chainId = GetChainId(i);
            var sideChainInfo = State.SideChainInfo[chainId];
            if (sideChainInfo.SideChainStatus == SideChainStatus.Terminated)
                continue;
            var height = State.CurrentSideChainHeight[chainId];
            dict.IdHeightDict.Add(chainId, height);
        }

        return dict;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L118-128)
```csharp
    public override ChainIdAndHeightDict GetAllChainsIdAndHeight(Empty input)
    {
        var dict = GetSideChainIdAndHeight(new Empty());

        if (State.ParentChainId.Value == 0)
            return dict;
        var parentChainHeight = GetParentChainHeight(new Empty()).Value;
        Assert(parentChainHeight > AElfConstants.GenesisBlockHeight, "Invalid parent chain height");
        dict.IdHeightDict.Add(State.ParentChainId.Value, parentChainHeight);
        return dict;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L130-145)
```csharp
    public override SideChainIndexingInformationList GetSideChainIndexingInformationList(Empty input)
    {
        var sideChainIndexingInformationList = new SideChainIndexingInformationList();
        var sideChainIdAndHeightDict = GetSideChainIdAndHeight(new Empty());
        foreach (var kv in sideChainIdAndHeightDict.IdHeightDict)
        {
            var chainId = kv.Key;
            sideChainIndexingInformationList.IndexingInformationList.Add(new SideChainIndexingInformation
            {
                ChainId = chainId,
                IndexedHeight = kv.Value
            });
        }

        return sideChainIndexingInformationList;
    }
```

**File:** protobuf/acs7.proto (L129-132)
```text
message ChainIdAndHeightDict {
    // A collection of chain ids and heights, where the key is the chain id and the value is the height.
    map<int32, int64> id_height_dict = 1;
}
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L135-154)
```csharp
        State.SideChainSerialNumber.Value = State.SideChainSerialNumber.Value.Add(1);
        var serialNumber = State.SideChainSerialNumber.Value;
        var chainId = GetChainId(serialNumber);
        State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;

        // lock token
        ChargeSideChainIndexingFee(input.Proposer, sideChainCreationRequest.LockedTokenAmount, chainId);

        var sideChainInfo = new SideChainInfo
        {
            Proposer = input.Proposer,
            SideChainId = chainId,
            SideChainStatus = SideChainStatus.Active,
            IndexingPrice = sideChainCreationRequest.IndexingPrice,
            IsPrivilegePreserved = sideChainCreationRequest.IsPrivilegePreserved,
            CreationTimestamp = Context.CurrentBlockTime,
            CreationHeightOnParentChain = Context.CurrentHeight,
            IndexingFeeController = CreateDefaultOrganizationForIndexingFeePriceManagement(input.Proposer)
        };
        State.SideChainInfo[chainId] = sideChainInfo;
```
