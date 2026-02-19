### Title
Missing Authorization Check in RegisterElectionVotingEvent Allows Unauthorized Voting System Initialization

### Summary
The `RegisterElectionVotingEvent()` function lacks sender authorization checks, allowing any external address to register the critical miner election voting event before the legitimate Economic Contract initialization. While normally called during genesis block creation, the absence of authorization violates security principles and creates a front-running risk if initialization fails or is delayed.

### Finding Description
The `RegisterElectionVotingEvent()` method only validates that the voting event hasn't been registered yet, but performs no check on who is calling it: [1](#0-0) 

The function is intended to be called exclusively by the Economic Contract during system initialization: [2](#0-1) 

However, unlike other maintenance functions in the same contract that properly verify the caller's identity, `RegisterElectionVotingEvent()` lacks this critical check. For comparison, `SetProfitsReceiver` correctly validates the sender: [3](#0-2) 

Similarly, `UpdateCandidateInformation` and `UpdateMinersCount` enforce sender restrictions: [4](#0-3) [5](#0-4) 

The Economic Contract system name constant is available for proper authorization: [6](#0-5) 

### Impact Explanation
An unauthorized caller could register the miner election voting event before the legitimate Economic Contract initialization, compromising system integrity. While the voting parameters are hardcoded within the function, an attacker controls the timing and context of this critical initialization step. This breaks the intended initialization sequence where the Economic Contract should be the sole entity managing this setup.

The `MinerElectionVotingItemId` is computed based on transaction context, meaning an attacker's registration would generate different identifiers than expected. This violates the Authorization & Governance critical invariant requiring proper method authority enforcement and represents a fundamental breach of the principle of least privilege for system initialization functions.

### Likelihood Explanation
The function is a public RPC method accessible to any address with zero execution cost: [7](#0-6) 

While normal operation calls this during genesis block initialization atomically, several scenarios enable exploitation:
1. Partial initialization failure in the Economic Contract before reaching the `RegisterElectionVotingEvent` call
2. Blockchain restart or recovery scenarios where initialization sequencing may be disrupted
3. Testing or development environments with non-standard initialization flows

Tests confirm the only protection is the one-time registration flag, not sender verification: [8](#0-7) 

An attacker requires no special privileges, just needs to call the function before the Economic Contract does. The attack is trivial to execute with an Empty input parameter.

### Recommendation
Add sender authorization check at the beginning of `RegisterElectionVotingEvent()`:

```csharp
public override Empty RegisterElectionVotingEvent(Empty input)
{
    Assert(
        Context.GetContractAddressByName(SmartContractConstants.EconomicContractSystemName) == Context.Sender,
        "No permission.");
    Assert(!State.VotingEventRegistered.Value, "Already registered.");
    // ... rest of implementation
}
```

This follows the established pattern used by other maintenance methods in the contract and ensures only the Economic Contract can register the voting event. Add integration tests verifying that:
1. The Economic Contract can successfully call this method during initialization
2. External addresses receive "No permission" error when attempting to call it
3. The Economic Contract cannot call it twice (existing test covers this)

### Proof of Concept
**Required Initial State:**
- Election Contract deployed and initialized via `InitialElectionContract`
- Economic Contract deployed but initialization not yet complete or failed before calling `RegisterElectionVotingEvent`
- Voting event not yet registered (`State.VotingEventRegistered.Value == false`)

**Attack Steps:**
1. Attacker calls `ElectionContract.RegisterElectionVotingEvent(new Empty())`
2. Transaction succeeds, sets `State.VotingEventRegistered.Value = true`
3. Later, when Economic Contract attempts legitimate initialization via `RegisterElectionVotingEvent.Send(new Empty())`, it fails with "Already registered."

**Expected vs Actual:**
- **Expected:** Only Economic Contract can register the voting event during initialization
- **Actual:** Any external address can successfully register the voting event first

**Success Condition:**
The attacker's transaction returns success status, and subsequent calls (including from Economic Contract) fail with the "Already registered" error, demonstrating the attacker successfully front-ran the legitimate initialization.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L54-76)
```csharp
    public override Empty RegisterElectionVotingEvent(Empty input)
    {
        Assert(!State.VotingEventRegistered.Value, "Already registered.");

        State.VoteContract.Value = Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName);

        var votingRegisterInput = new VotingRegisterInput
        {
            IsLockToken = false,
            AcceptedCurrency = Context.Variables.NativeSymbol,
            TotalSnapshotNumber = long.MaxValue,
            StartTimestamp = TimestampHelper.MinValue,
            EndTimestamp = TimestampHelper.MaxValue
        };
        State.VoteContract.Register.Send(votingRegisterInput);

        State.MinerElectionVotingItemId.Value = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(votingRegisterInput),
            HashHelper.ComputeFrom(Context.Self));

        State.VotingEventRegistered.Value = true;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L83-88)
```csharp
    public override Empty UpdateCandidateInformation(UpdateCandidateInformationInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) ==
            Context.Sender || Context.Sender == GetEmergencyResponseOrganizationAddress(),
            "Only consensus contract can update candidate information.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L149-156)
```csharp
    public override Empty UpdateMinersCount(UpdateMinersCountInput input)
    {
        Context.LogDebug(() =>
            $"Consensus Contract Address: {Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName)}");
        Context.LogDebug(() => $"Sender Address: {Context.Sender}");
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
            "Only consensus contract can update miners count.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L379-383)
```csharp
    public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName) == Context.Sender,
            "No permission.");
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L180-185)
```csharp
    private void RegisterElectionVotingEvent()
    {
        State.ElectionContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        State.ElectionContract.RegisterElectionVotingEvent.Send(new Empty());
    }
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L56-56)
```csharp
    public static readonly string EconomicContractSystemName = GetStringName(EconomicContractSystemHashName);
```

**File:** protobuf/election_contract.proto (L25-27)
```text
    // Register a new voting item through vote contract.
    rpc RegisterElectionVotingEvent (google.protobuf.Empty) returns (google.protobuf.Empty) {
    }
```

**File:** test/AElf.Contracts.Election.Tests/GQL/ElectionTests.cs (L30-37)
```csharp
    [Fact]
    public async Task ElectionContract_RegisterElectionVotingEvent_Register_Twice_Test()
    {
        var registerAgainRet =
            await ElectionContractStub.RegisterElectionVotingEvent.SendAsync(new Empty());
        registerAgainRet.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        registerAgainRet.TransactionResult.Error.ShouldContain("Already registered.");
    }
```
