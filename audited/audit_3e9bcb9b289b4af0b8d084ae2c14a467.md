### Title
Front-Running Attack via User-Controlled Token Field Enables Proposal DoS and Hijacking

### Summary
The `GenerateProposalId` function in all three governance contracts (Parliament, Association, Referendum) uses a user-controlled `Token` field to generate deterministic proposal IDs. This allows attackers to monitor the mempool, front-run legitimate proposal creation transactions by using the same token value, and either block proposal creation entirely or hijack pre-coordinated proposal IDs with malicious content.

### Finding Description

The vulnerability exists in the proposal ID generation mechanism used across all governance contracts. [1](#0-0) 

The `GenerateProposalId` function uses either the user-provided `Token` field or computes a hash from the entire input. When a user provides a `Token` value, the proposal ID becomes deterministic and predictable. [2](#0-1) 

The `Token` field is designed to allow proposal IDs to be calculated before proposing, enabling coordination. However, this creates a critical vulnerability. [3](#0-2) 

The `CreateNewProposal` function only checks if a proposal ID already exists, but does NOT verify that the proposal content matches what was expected for that token. An attacker can exploit this by:

1. Monitoring the mempool for `CreateProposal` transactions containing a `Token` field
2. Extracting the token value from the victim's transaction
3. Creating their own proposal with the same token but different content (ToAddress, ContractMethodName, Params)
4. Paying higher gas fees to ensure their transaction is mined first
5. The victim's transaction then fails at the assertion check

The same vulnerability exists in Association and Referendum contracts: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

The public entry point is accessible to all authorized proposers: [8](#0-7) 

### Impact Explanation

**Denial of Service Impact:**
- Any user attempting to create a proposal with a `Token` field can be blocked indefinitely by an attacker
- Legitimate governance proposals cannot be created if continuously front-run
- Critical time-sensitive proposals may expire before successfully being created

**Proposal Hijacking Impact:**
- If users pre-calculate proposal IDs and coordinate with voters off-chain (the intended use case for the Token field), attackers can create a different proposal with the same ID
- Voters who were coordinated to approve proposal ID `X` would unknowingly approve the attacker's malicious proposal instead of the intended one
- This breaks the fundamental trust model of pre-coordinated governance actions

**Governance Integrity Impact:**
- Attackers can selectively block proposals from specific organizations or proposers
- The governance system becomes unreliable when users attempt to use the deterministic proposal ID feature
- Creates a griefing vector with minimal cost to attackers but high cost to legitimate users

**Affected Parties:**
- All governance organizations (Parliament, Association, Referendum)
- Proposers attempting to use deterministic proposal IDs
- Voters who coordinate on pre-calculated proposal IDs
- The entire protocol's governance mechanism

**Severity Justification:**
HIGH severity due to:
- Direct impact on core governance functionality
- Enables both DoS and manipulation attacks
- Low attack cost (only gas fees for front-running)
- High impact on protocol security and governance integrity
- Affects all three governance contract types

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to monitor the public mempool for pending transactions
- Sufficient funds to pay higher gas fees for front-running
- No special privileges or access required - any user can execute this attack

**Attack Complexity:**
- LOW - Standard front-running attack pattern well-understood in blockchain
- Automated tools exist for mempool monitoring and front-running
- Attack requires only basic transaction manipulation skills

**Feasibility Conditions:**
- Attack succeeds whenever a user provides a `Token` field in their CreateProposalInput
- No additional preconditions required
- Works on any governance organization (Parliament, Association, or Referendum)
- Transaction ordering vulnerability is inherent to blockchain architecture

**Detection and Operational Constraints:**
- Attack is difficult to detect until victim's transaction fails
- No on-chain mechanism to prove front-running occurred
- Victim may not realize their proposal was hijacked if they don't verify proposal content
- No rate limiting or anti-front-running protections in place

**Probability Reasoning:**
HIGH probability because:
- The `Token` field is part of the public ACS3 standard and documented for use
- Users are explicitly encouraged to use it for proposal ID pre-calculation
- Front-running is a common and well-known attack vector
- Attack has immediate financial incentive (blocking competitors' governance proposals)
- No technical barriers prevent execution

### Recommendation

**Immediate Mitigation:**

1. **Add Content Verification:** Modify `CreateNewProposal` to store a commitment hash of the proposal content when using a token, and verify it matches:

```csharp
private Hash CreateNewProposal(CreateProposalInput input)
{
    CheckCreateProposalInput(input);
    var proposalId = GenerateProposalId(input);
    
    if (input.Token != null)
    {
        // If using token, verify proposal content matches expected
        var contentHash = HashHelper.ComputeFrom(input);
        var existingCommitment = State.ProposalCommitments[proposalId];
        
        if (existingCommitment != null)
        {
            Assert(existingCommitment == contentHash, 
                "Proposal content does not match token commitment.");
        }
        else
        {
            State.ProposalCommitments[proposalId] = contentHash;
        }
    }
    
    Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
    // ... rest of method
}
```

2. **Alternative: Remove Token Field:** If deterministic proposal IDs are not critical, consider deprecating the `Token` field entirely and always use `HashHelper.ComputeFrom(input)`, which includes all proposal content in the hash calculation.

3. **Add Proposer Binding:** Alternatively, bind the token to the proposer address:
```csharp
private Hash GenerateProposalId(CreateProposalInput input)
{
    var tokenWithProposer = input.Token != null 
        ? HashHelper.ConcatAndCompute(input.Token, HashHelper.ComputeFrom(Context.Sender))
        : HashHelper.ComputeFrom(input);
    return Context.GenerateId(Context.Self, tokenWithProposer);
}
```

**Invariant Checks to Add:**
- When `Token` is provided, proposal content MUST match any previously committed content for that token
- Proposal IDs MUST be collision-resistant even with adversarial token selection
- Two proposals with the same ID MUST have identical content (ToAddress, ContractMethodName, Params, OrganizationAddress)

**Test Cases to Add:**
1. Test that creating two proposals with same token but different content fails appropriately
2. Test that legitimate re-submission with same token and same content succeeds
3. Test front-running scenario where attacker attempts to hijack proposal ID
4. Test that proposal content verification prevents hijacking attacks
5. Fuzz test with adversarial token values to ensure no collision vulnerabilities

### Proof of Concept

**Initial State:**
- Parliament organization exists with Alice as authorized proposer
- Bob (attacker) is also an authorized proposer
- Alice wants to create a proposal to transfer 100 ELF to her address using Token = 0x123abc

**Attack Sequence:**

**Step 1:** Alice broadcasts transaction:
```
CreateProposal({
    Token: 0x123abc,
    ToAddress: AliceContract,
    ContractMethodName: "Transfer",
    Params: "Transfer(Alice, 100 ELF)",
    OrganizationAddress: DefaultOrg,
    ExpiredTime: Now + 7 days
})
```

**Step 2:** Bob monitors mempool, sees Alice's transaction, extracts Token = 0x123abc

**Step 3:** Bob front-runs with higher gas fee:
```
CreateProposal({
    Token: 0x123abc,
    ToAddress: BobContract,
    ContractMethodName: "Transfer", 
    Params: "Transfer(Bob, 100 ELF)",
    OrganizationAddress: DefaultOrg,
    ExpiredTime: Now + 7 days
})
```

**Step 4:** Bob's transaction mines first due to higher gas
- ProposalId = GenerateProposalId(0x123abc) = Hash_X
- State.Proposals[Hash_X] = Bob's proposal (stealing funds to Bob)

**Step 5:** Alice's transaction executes
- ProposalId = GenerateProposalId(0x123abc) = Hash_X (same ID!)
- Assertion fails: `Assert(State.Proposals[Hash_X] == null, "Proposal already exists.")`
- Alice's transaction reverts

**Expected Result:** Alice successfully creates proposal with ID Hash_X

**Actual Result:** Alice's transaction fails. Proposal Hash_X now contains Bob's malicious content. If Alice had pre-coordinated with voters to approve Hash_X, they would unknowingly approve Bob's proposal.

**Success Condition for Attack:** 
- Bob's proposal exists with ID Hash_X
- Alice's proposal creation fails
- Voters coordinated on Hash_X approve Bob's proposal instead of Alice's intended proposal

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

**File:** protobuf/acs3.proto (L91-92)
```text
    // The token is for proposal id generation and with this token, proposal id can be calculated before proposing.
    aelf.Hash token = 7;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L140-143)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L163-163)
```csharp
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L154-157)
```csharp
    private Hash GenerateProposalId(CreateProposalInput input)
    {
        return Context.GenerateId(Context.Self, input.Token ?? HashHelper.ComputeFrom(input));
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L163-163)
```csharp
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L61-66)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
    }
```
