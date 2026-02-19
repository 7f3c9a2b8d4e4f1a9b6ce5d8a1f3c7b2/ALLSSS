### Title
Malicious System Contract Can Create Unlimited Duplicate Proposals Through Transaction-Based ID Generation

### Summary
The `CreateProposalBySystemContract` function lacks content-based deduplication, allowing a malicious system contract to create unlimited proposals with identical content. Each transaction generates a unique proposal ID due to the inclusion of `OriginTransactionId` in the ID generation logic, bypassing the duplicate check that only validates proposal ID uniqueness. This enables vote splitting attacks and governance pollution.

### Finding Description

The vulnerability exists in the proposal ID generation and duplicate detection mechanism:

**Root Cause:** [1](#0-0) 

The `GenerateProposalId` function uses `Context.GenerateId`, which internally concatenates `OriginTransactionId` with the contract address and input hash: [2](#0-1) 

This means each transaction produces a different proposal ID, even with identical input parameters.

**Insufficient Protection:** [3](#0-2) 

The duplicate check at line 243 only validates: `Assert(State.Proposals[proposalId] == null, "Proposal already exists.")`. Since proposal IDs are transaction-specific, this check cannot prevent content duplication across different transactions.

**Entry Point:** [4](#0-3) 

A system contract can call `CreateProposalBySystemContract` multiple times with identical `CreateProposalBySystemContractInput`, creating multiple proposals with the same content but different IDs.

**Evidence:** [5](#0-4) 

Test case explicitly demonstrates that proposals with the same input successfully create multiple distinct proposals.

### Impact Explanation

**Governance Disruption:**
- **Vote Splitting**: Parliament members voting on identical proposals will have their votes distributed across multiple proposal IDs, potentially preventing any single proposal from reaching the approval threshold defined in `ProposalReleaseThreshold`
- **Governance Pollution**: The proposal space becomes cluttered with duplicates, making it difficult to identify legitimate unique proposals
- **Resource Exhaustion**: Unlimited state storage consumption until proposals expire, as each proposal is stored separately

**Attack Scenario:**
If 10 identical proposals are created and parliament has 100 members:
- Without attack: 70 approvals on one proposal → passes (assuming 67% threshold)
- With attack: 7-10 approvals per proposal → none pass threshold

**Affected Parties:**
- Parliament governance organizations relying on proposal uniqueness
- System contracts that don't implement their own duplicate prevention (unlike Genesis contract which has protection at line 315 of BasicContractZero_Helper.cs) [6](#0-5) 

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must control or compromise a system contract authorized to call `CreateProposalBySystemContract`
- System contracts are verified at runtime: [7](#0-6) 

**Attack Complexity:**
Once a malicious system contract exists, exploitation is trivial - simply invoke `CreateProposalBySystemContract` multiple times with identical input in separate transactions.

**Feasibility Conditions:**
- **System Contract Deployment**: Requires governance approval to deploy a malicious contract, OR exploitation of a vulnerability in an existing system contract
- **Authorization Check Bypass**: The check at line 72 validates the `origin_proposer` has authority, but doesn't limit proposal frequency or detect duplicates [8](#0-7) 

**Detection Constraints:**
- Proposals are publicly visible on-chain
- However, distinguishing intentional re-proposals from malicious duplicates may be difficult
- No rate limiting or cooldown period exists between proposal submissions

**Likelihood Assessment:**
Medium-Low probability, as it requires system contract compromise. However, the impact when exploited is significant for governance integrity.

### Recommendation

**1. Implement Content-Based Deduplication:**
Add a content hash to proposal tracking in `Parliament_Helper.cs`:

```csharp
private Hash CreateNewProposal(CreateProposalInput input)
{
    CheckCreateProposalInput(input);
    var proposalId = GenerateProposalId(input);
    
    // Add content-based deduplication
    var contentHash = HashHelper.ComputeFrom(new ProposalContentHash
    {
        ContractMethodName = input.ContractMethodName,
        ToAddress = input.ToAddress,
        Params = input.Params,
        OrganizationAddress = input.OrganizationAddress
    });
    
    // Check if active proposal with same content exists
    var existingProposalId = State.ProposalContentToId[contentHash];
    if (existingProposalId != null)
    {
        var existingProposal = State.Proposals[existingProposalId];
        Assert(existingProposal == null || !Validate(existingProposal), 
            "Active proposal with identical content already exists.");
    }
    
    // Create proposal and store content mapping
    var proposal = new ProposalInfo { /* ... */ };
    State.Proposals[proposalId] = proposal;
    State.ProposalContentToId[contentHash] = proposalId;
    
    return proposalId;
}
```

**2. Add Proposal Rate Limiting:**
Track proposal creation timestamps per proposer and enforce minimum intervals.

**3. Clear Content Mapping on Release:**
When a proposal is released or expires, remove its content hash mapping to allow re-proposing the same action later: [9](#0-8) 

**4. Add Test Cases:**
Create tests specifically for `CreateProposalBySystemContract` duplicate detection across multiple transactions.

### Proof of Concept

**Initial State:**
- Parliament contract initialized with default organization
- Malicious system contract deployed and authorized
- Target proposal: Transfer 100 ELF to attacker

**Transaction Sequence:**

**Transaction 1:**
```
Call: MaliciousSystemContract.Attack()
  └─> Parliament.CreateProposalBySystemContract(
        ProposalInput: {
          ToAddress: TokenContract,
          ContractMethodName: "Transfer",
          Params: {To: Attacker, Amount: 100},
          OrganizationAddress: DefaultOrg,
          ExpiredTime: Now + 7 days
        },
        OriginProposer: AttackerAddress
      )
Result: ProposalId = Hash(TX1_ID || Parliament || Input_Hash)
Status: SUCCESS - Proposal created
```

**Transaction 2-10:**
```
Repeat same call 9 more times in separate transactions
Each generates: ProposalId = Hash(TXn_ID || Parliament || Input_Hash)
Status: SUCCESS - All 10 proposals created with different IDs
```

**Expected vs Actual:**
- **Expected**: Second call should fail with "Active proposal with identical content already exists"
- **Actual**: All 10 proposals succeed, each with unique ID but identical content

**Success Condition:**
Query `GetProposal` for all 10 proposal IDs shows identical `ToAddress`, `ContractMethodName`, `Params`, and `OrganizationAddress`, confirming duplicate content with different IDs.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L220-223)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L225-253)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            ToAddress = input.ToAddress,
            OrganizationAddress = input.OrganizationAddress,
            ProposalId = proposalId,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        State.Proposals[proposalId] = proposal;
        Context.Fire(new ProposalCreated
        {
            ProposalId = proposalId, 
            OrganizationAddress = input.OrganizationAddress,
            Title = input.Title,
            Description = input.Description
        });
        return proposalId;
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L139-146)
```csharp
    public Hash GenerateId(Address contractAddress, IEnumerable<byte> bytes)
    {
        var contactedBytes = OriginTransactionId.Value.Concat(contractAddress.Value);
        var enumerable = bytes as byte[] ?? bytes?.ToArray();
        if (enumerable != null)
            contactedBytes = contactedBytes.Concat(enumerable);
        return HashHelper.ComputeFrom(contactedBytes.ToArray());
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L68-76)
```csharp
    public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Unauthorized to propose.");
        AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);

        var proposalId = CreateNewProposal(input.ProposalInput);
        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-145)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

        return new Empty();
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L316-324)
```csharp
        //"Proposal with same input."
        {
            createProposalInput.OrganizationAddress = organizationAddress;
            var transactionResult1 = await ParliamentContractStub.CreateProposal.SendAsync(createProposalInput);
            transactionResult1.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var transactionResult2 = await ParliamentContractStub.CreateProposal.SendAsync(createProposalInput);
            transactionResult2.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L312-342)
```csharp
    private void SendUserContractProposal(Hash proposingInputHash, string releaseMethodName, ByteString @params)
    {
        var registered = State.ContractProposingInputMap[proposingInputHash];
        Assert(registered == null || Context.CurrentBlockTime >= registered.ExpiredTime, "Already proposed.");
        var proposedInfo = new ContractProposingInput
        {
            Proposer = Context.Self,
            Status = ContractProposingInputStatus.CodeCheckProposed,
            ExpiredTime = Context.CurrentBlockTime.AddSeconds(GetCodeCheckProposalExpirationTimePeriod()),
            Author = Context.Sender
        };
        State.ContractProposingInputMap[proposingInputHash] = proposedInfo;

        var codeCheckController = State.CodeCheckController.Value;
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput = new CreateProposalInput
            {
                ToAddress = Context.Self,
                ContractMethodName = releaseMethodName,
                Params = @params,
                OrganizationAddress = codeCheckController.OwnerAddress,
                ExpiredTime = proposedInfo.ExpiredTime
            },
            OriginProposer = Context.Self
        };

        Context.SendInline(codeCheckController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput);
    }
```
