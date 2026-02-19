### Title
Insufficient Duplicate Proposal Detection Allows Governance Spam and Vote Dilution

### Summary
The Referendum contract's proposal creation mechanism allows whitelisted proposers to create multiple distinct proposals with identical substantive content. The duplicate check only validates proposal ID uniqueness, not content uniqueness, enabling an attacker to spam the governance system with near-identical or completely identical proposals that split votes and create confusion.

### Finding Description

The vulnerability exists in the proposal ID generation and duplicate detection logic in the Referendum contract. [1](#0-0) 

The `GenerateProposalId` method uses `Context.GenerateId` which incorporates the `OriginTransactionId` in its hash computation: [2](#0-1) 

This means each transaction generates a unique proposal ID even with identical input parameters. The duplicate check only validates proposal ID uniqueness: [3](#0-2) 

The validation checks only enforce field constraints (length limits, valid addresses, expiration time), not content uniqueness: [4](#0-3) [5](#0-4) 

This behavior is confirmed by existing test cases that successfully create multiple proposals with identical input: [6](#0-5) 

### Impact Explanation

A malicious or compromised whitelisted proposer can exploit this to:

1. **Governance Spam**: Create unlimited proposals with identical substantive content (same `contract_method_name`, `to_address`, `params`, `organization_address`) but different `title`, `description`, `proposal_description_url`, or by simply submitting identical proposals in separate transactions.

2. **Vote Dilution**: Split community votes across multiple identical proposals, potentially preventing any single proposal from reaching approval thresholds while the same action could have passed if votes were consolidated.

3. **User Confusion**: Voters face multiple proposals executing the same action with different or identical metadata, making informed voting difficult.

4. **Resource Exhaustion**: Each duplicate proposal consumes storage and requires processing, cluttering the governance system.

5. **Strategic Manipulation**: An attacker could create multiple versions of their preferred proposal while creating only one version of competing proposals, skewing vote distribution.

The severity is **Medium** because:
- Requires whitelisted proposer access (elevated but not full admin privilege)
- Causes operational disruption rather than direct fund loss
- Undermines governance integrity and effectiveness
- Can be executed repeatedly with low cost

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be added to the organization's proposer whitelist [7](#0-6) 

**Attack Complexity:** Low - simply call `CreateProposal` multiple times with identical or nearly-identical input.

**Feasibility:** 
- Transaction fees apply via ACS1 method fee mechanism, but these are typically modest and acceptable cost for a determined attacker
- No rate limiting exists
- No content-based duplicate detection exists
- Confirmed exploitable in current implementation by test cases

**Detection Constraints:** 
- Attack is visible on-chain but may not be immediately recognized as malicious
- Multiple similar proposals might appear legitimate initially

**Probability:** Medium-High once attacker gains whitelisted proposer status. While whitelist access is a barrier, compromised or malicious whitelisted proposers (insider threat) are realistic scenarios in governance systems.

### Recommendation

Implement content-based duplicate detection that prevents creating proposals with identical substantive content:

1. **Add Content Hash Tracking**: Maintain a mapping of content hashes (from substantive fields only) to proposal IDs for active proposals:
   - Hash should include: `contract_method_name`, `to_address`, `params`, `organization_address`
   - Exclude: `title`, `description`, `proposal_description_url`, `expired_time`

2. **Check Content Duplicates**: In `CreateNewProposal`, before line 163, add:
   ```csharp
   var contentHash = HashHelper.ComputeFrom(new ProposalContentForDuplicateCheck {
       ContractMethodName = input.ContractMethodName,
       ToAddress = input.ToAddress,
       Params = input.Params,
       OrganizationAddress = input.OrganizationAddress
   });
   Assert(!IsActiveProposalWithContent(contentHash), "Proposal with identical content already exists.");
   ```

3. **Clean Up on Release/Expire**: Remove content hash from tracking when proposal is released or expired to allow re-proposing after resolution.

4. **Alternative Option**: Implement rate limiting per proposer (e.g., max N proposals per organization per time period).

5. **Add Test Cases**: Create tests that attempt to create duplicate proposals with:
   - Identical input in separate transactions (should fail)
   - Same substantive content with different titles (should fail)
   - Same content after previous proposal expired (should succeed)

### Proof of Concept

**Initial State:**
- Organization exists with whitelisted proposer
- Proposer has approval from token holders (via allowance mechanism)

**Attack Steps:**

1. **Identical Proposal Attack:**
   ```
   Transaction 1: Call CreateProposal(input)
   Result: Proposal ID = Hash(TxId1 + Contract + Hash(input))
   Status: Success
   
   Transaction 2: Call CreateProposal(input) [exact same input]
   Result: Proposal ID = Hash(TxId2 + Contract + Hash(input))
   Status: Success [Different TxId creates different proposal ID]
   ```

2. **Near-Identical Proposal Attack:**
   ```
   Transaction 1: CreateProposal({...substantive_fields, title: "Proposal A"})
   Transaction 2: CreateProposal({...substantive_fields, title: "Proposal B"})
   Transaction 3: CreateProposal({...substantive_fields, title: "Proposal C"})
   
   All succeed with different proposal IDs but execute the same action
   ```

**Expected Result:** Second call should fail with "Proposal with identical content already exists"

**Actual Result:** All calls succeed, creating multiple distinct proposals with identical or nearly-identical content

**Success Condition:** The test case explicitly demonstrates this behavior succeeds: [6](#0-5) 

Both transactions return `TransactionResultStatus.Mined`, confirming the vulnerability is exploitable in the current implementation.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L104-113)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L154-157)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L159-187)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ToAddress = input.ToAddress,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            OrganizationAddress = input.OrganizationAddress,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L189-198)
```csharp
    private void CheckCreateProposalInput(CreateProposalInput input)
    {
        // Check the length of title
        Assert(input.Title.Length <= ReferendumConstants.MaxLengthForTitle, "Title is too long.");
        // Check the length of description
        Assert(input.Description.Length <= ReferendumConstants.MaxLengthForDescription, "Description is too long.");
        // Check the length of description url
        Assert(input.ProposalDescriptionUrl.Length <= ReferendumConstants.MaxLengthForProposalDescriptionUrl,
            "Description url is too long.");
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L200-205)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "Organization not found.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
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

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L214-218)
```csharp
            var transactionResult1 = await ReferendumContractStub.CreateProposal.SendAsync(createProposalInput);
            transactionResult1.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var transactionResult2 = await ReferendumContractStub.CreateProposal.SendAsync(createProposalInput);
            transactionResult2.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
```
