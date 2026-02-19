### Title
Chain ID Collision Causes Side Chain Data Overwrite and DoS in GetSideChainIdAndHeight

### Summary
The `GetChainId()` function uses hash-based generation that can produce duplicate chain IDs for different serial numbers, as demonstrated in existing unit tests. When collisions occur, the second side chain creation silently overwrites the first chain's data in `State.SideChainInfo`, causing permanent loss of the original chain's configuration and locked funds. Subsequently, `GetSideChainIdAndHeight()` throws an exception when attempting to add the duplicate chain ID to the dictionary, causing a denial-of-service on critical cross-chain view functions.

### Finding Description

The vulnerability exists in the chain ID generation mechanism used during side chain creation: [1](#0-0) 

The `GetChainId()` function uses `serialNumber.GetHashCode()` which is not cryptographically unique and can produce collisions. The contract wrapper calls this with an offset: [2](#0-1) 

The existing unit tests explicitly demonstrate hash collisions occur: [3](#0-2) 

During side chain creation, the contract generates a chain ID from an incremented serial number but performs **no validation** to check if this chain ID already exists: [4](#0-3) 

When `GetSideChainIdAndHeight()` iterates through all serial numbers and encounters a collision, it attempts to add the same chain ID twice to a dictionary: [5](#0-4) 

The `IdHeightDict` is a protobuf map that generates as a dictionary-like structure in C#: [6](#0-5) 

Dictionary `Add()` operations throw `ArgumentException` when the key already exists, causing the view function to fail completely.

### Impact Explanation

**Data Loss and Fund Lock:**
- When a collision occurs during `CreateSideChain()`, the second side chain's `SideChainInfo` overwrites the first chain's data at `State.SideChainInfo[chainId]`
- The original side chain's configuration (proposer address, creation height, indexing price, locked tokens, status) is permanently lost
- Funds locked via `ChargeSideChainIndexingFee()` for the first chain become inaccessible as the virtual address is based on chain ID, but the mapping now points to the second chain's data
- The original chain's creator loses control and cannot dispose the chain or retrieve locked funds

**Denial of Service:**
- After collision, `GetSideChainIdAndHeight()` throws an exception when called, breaking all functionality that depends on it
- `GetAllChainsIdAndHeight()` also fails as it calls `GetSideChainIdAndHeight()`
- `GetSideChainIndexingInformationList()` fails, disrupting cross-chain indexing operations
- Cross-chain data indexing and validation flows become blocked, preventing parent-child chain communication

**Cross-Chain Integrity Violation:**
- Two different side chains would share the same chain ID, violating the fundamental uniqueness invariant
- Cross-chain merkle proof verification becomes unreliable when the same chain ID maps to different chain data
- Parent chain cannot correctly distinguish between the two side chains

### Likelihood Explanation

**Probability:**
- Hash collisions via `GetHashCode()` are mathematically possible and explicitly demonstrated in the codebase's own unit tests showing `long.MinValue` and `long.MaxValue` produce identical chain IDs
- While collisions between small sequential serial numbers (1, 2, 3...) are less likely, the probability increases as more side chains are created over time
- With sufficiently large serial numbers or specific hash distribution patterns, collisions become increasingly probable

**Attacker Capabilities:**
- No attacker action is required to trigger the vulnerability - it occurs naturally when the hash function produces a collision
- Any authorized entity creating side chains (passing governance approval) can unknowingly trigger this by normal side chain creation operations
- The vulnerability is passive - it depends on mathematical properties of the hash function rather than malicious intent

**Execution Practicality:**
- The vulnerability triggers automatically during legitimate side chain creation if a collision occurs
- No special permissions beyond normal side chain creation authority are needed
- Once triggered, the DoS is persistent and affects all subsequent calls to the affected view functions

### Recommendation

**1. Add Collision Detection in CreateSideChain:**
```csharp
// In CreateSideChain, after line 137
var chainId = GetChainId(serialNumber);
Assert(State.SideChainInfo[chainId] == null, "Chain ID collision detected. Contact system administrators.");
```

**2. Implement Deterministic Chain ID Generation:**
Replace hash-based generation with a deterministic, collision-free approach:
- Use a cryptographic hash of `(Context.ChainId || serialNumber)` and take the first N bytes
- Or use `Context.ChainId + serialNumber` directly as chain ID if the value space permits
- Or implement retry logic: if collision detected, increment a nonce and regenerate until unique

**3. Add Duplicate Key Protection in GetSideChainIdAndHeight:**
```csharp
// In GetSideChainIdAndHeight, replace line 112
if (!dict.IdHeightDict.ContainsKey(chainId))
    dict.IdHeightDict.Add(chainId, height);
else
    Context.LogDebug(() => $"Duplicate chain ID {chainId} detected for serial {i}");
```

**4. Add Regression Tests:**
- Test that sequential serial numbers produce unique chain IDs
- Test that CreateSideChain rejects operations when a collision would occur
- Test GetSideChainIdAndHeight behavior with intentionally colliding chain IDs

### Proof of Concept

**Required Initial State:**
- CrossChain contract deployed and initialized
- Side chain creation governance in place

**Step 1:** Create first side chain
- Proposer calls `RequestSideChainCreation()` with valid parameters
- Governance approves and releases proposal
- `CreateSideChain()` executes with serial number N, generating chainId X
- `State.SideChainInfo[X]` stores first side chain data with locked funds F1

**Step 2:** Continue creating side chains until collision
- Create subsequent side chains incrementing serial number
- Eventually serial number M produces the same chainId X due to hash collision
- `GetChainId(M)` returns X (same as `GetChainId(N)`)

**Step 3:** Collision triggers data overwrite
- Second `CreateSideChain()` executes with serial number M
- Generates chainId X (duplicate)
- `State.SideChainInfo[X] = sideChainInfo` overwrites first chain's data (line 154)
- First side chain's data is permanently lost
- Funds F1 remain locked but inaccessible under the overwritten chain info

**Step 4:** DoS on GetSideChainIdAndHeight
- Anyone calls `GetSideChainIdAndHeight()`
- Loop iterates through serial numbers 1 to M
- When i=N, adds (chainId X, height1) to dict
- When i=M, attempts `dict.IdHeightDict.Add(X, height2)` 
- **Exception thrown:** "An item with the same key has already been added"
- Function fails completely, blocking all cross-chain height queries

**Expected Result:** Unique chain IDs, no data loss, view functions operational

**Actual Result:** Chain data overwritten, funds locked, view functions throw exceptions

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L355-358)
```csharp
    private int GetChainId(long serialNumber)
    {
        return ChainHelper.GetChainId(serialNumber + Context.ChainId);
    }
```

**File:** test/AElf.Types.Tests/Helper/ChainHelperTests.cs (L37-38)
```csharp
            var chainIdMinValue = ChainHelper.GetChainId(long.MinValue);
            chainIdMinValue.ShouldBe(chainIdMaxValue);
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

**File:** protobuf/acs7.proto (L129-132)
```text
message ChainIdAndHeightDict {
    // A collection of chain ids and heights, where the key is the chain id and the value is the height.
    map<int32, int64> id_height_dict = 1;
}
```
