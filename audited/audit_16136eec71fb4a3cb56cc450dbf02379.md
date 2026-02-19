# Audit Report

## Title
Candidate Admin Separation Invariant Can Be Bypassed Through AnnounceElectionFor

## Summary
The Election contract enforces an invariant that "Candidate cannot be others' admin" in the `AnnounceElection` method, but this critical check is absent from `AnnounceElectionFor` and `SetCandidateAdmin`. This allows any candidate to bypass the restriction and become an admin for multiple candidates, centralizing control over candidate slots and violating the intended decentralization guarantees of the election system.

## Finding Description

The Election contract maintains two related state mappings for managing candidate administration relationships. [1](#0-0) 

The `AnnounceElection` method explicitly enforces the separation invariant through a validation check that prevents addresses already managing candidates from becoming candidates themselves. [2](#0-1) 

However, the `AnnounceElectionFor` method completely omits this validation check, allowing the admin parameter to be set without verifying whether that admin is already a candidate. [3](#0-2) 

Similarly, `SetCandidateAdmin` allows changing a candidate's admin without checking if the new admin is already a candidate managing others. [4](#0-3) 

**Exploitation Sequence:**
1. Alice calls `AnnounceElection(Alice)` - The check at line 102 passes because `ManagedCandidatePubkeysMap[Alice]` is initially null
2. After execution, Alice is a candidate and `ManagedCandidatePubkeysMap[Alice]` contains only Alice's pubkey
3. Alice calls `AnnounceElectionFor(BobPubkey, Alice)` - No validation prevents Alice from managing additional candidates
4. Result: `ManagedCandidatePubkeysMap[Alice]` now contains both Alice's and Bob's pubkeys, violating the invariant

Both methods are publicly accessible RPC endpoints. [5](#0-4) 

## Impact Explanation

The candidate admin role carries significant privileges that enable centralization of control:

**Authorization Control:**
The admin can unilaterally set profit receivers for all managed candidates. [6](#0-5) 

The admin can force any managed candidate to quit the election. [7](#0-6) 

The admin can replace candidate public keys at will. [8](#0-7) 

**Governance Impact:**
- A single entity can control multiple candidate slots while appearing as separate candidates
- The admin can redirect mining rewards from managed candidates to their own address
- This undermines the decentralized election process by allowing vote manipulation through multiple controlled candidates
- Managed candidates lose autonomy over their candidacy, profits, and operational decisions

**Economic Impact:**
By setting profit receivers for managed candidates to their own address, the attacker can extract rewards earned by infrastructure they don't operate, effectively stealing mining rewards from legitimate node operators.

## Likelihood Explanation

**Accessibility:** Both `AnnounceElection` and `AnnounceElectionFor` are public RPC methods callable by any user without special privileges.

**Execution Requirements:** 
- Cost: Multiple candidate deposits (ElectionContractConstants.LockTokenForElection per candidate)
- Prerequisites: Sufficient token balance for deposits
- No timing constraints or complex state preconditions required

**Detection:** The vulnerability can be detected by querying managed pubkeys for candidate addresses. [9](#0-8) 

**Probability:** HIGH - The bypass requires only two simple transaction calls with no coordination or timing requirements. Any user with sufficient tokens can execute this attack immediately.

## Recommendation

Add the invariant validation check to both `AnnounceElectionFor` and `SetCandidateAdmin`:

```csharp
// In AnnounceElectionFor, before line 128:
var admin = input.Admin ?? Context.Sender;
Assert(State.ManagedCandidatePubkeysMap[admin] == null, "Candidate cannot be others' admin.");

// In SetCandidateAdmin, before line 42:
Assert(State.ManagedCandidatePubkeysMap[input.Admin] == null, "Candidate cannot be others' admin.");
```

Additionally, consider checking if the new admin is already a candidate by verifying their address is not derived from any candidate pubkey in the `Candidates` list.

## Proof of Concept

```csharp
[Fact]
public async Task BypassCandidateAdminSeparation()
{
    // Setup: Alice has tokens for candidate deposits
    var aliceKeyPair = SampleECKeyPairs.KeyPairs[0];
    var aliceAddress = Address.FromPublicKey(aliceKeyPair.PublicKey);
    var bobPubkey = SampleECKeyPairs.KeyPairs[1].PublicKey.ToHex();
    
    // Step 1: Alice announces election with herself as admin
    var announceResult = await ElectionContractStub.AnnounceElection.SendAsync(aliceAddress);
    announceResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify Alice is now managing herself
    var managedPubkeys1 = await ElectionContractStub.GetManagedPubkeys.CallAsync(aliceAddress);
    managedPubkeys1.Value.Count.ShouldBe(1);
    managedPubkeys1.Value[0].ToHex().ShouldBe(aliceKeyPair.PublicKey.ToHex());
    
    // Step 2: Alice announces election for Bob with herself as admin
    var announceForResult = await ElectionContractStub.AnnounceElectionFor.SendAsync(
        new AnnounceElectionForInput
        {
            Pubkey = bobPubkey,
            Admin = aliceAddress
        });
    announceForResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Alice now manages both herself AND Bob, violating the invariant
    var managedPubkeys2 = await ElectionContractStub.GetManagedPubkeys.CallAsync(aliceAddress);
    managedPubkeys2.Value.Count.ShouldBe(2); // Alice + Bob
    
    // Alice is both a candidate AND manages another candidate
    var candidateList = await ElectionContractStub.GetCandidates.CallAsync(new Empty());
    candidateList.Value.ShouldContain(ByteString.CopyFrom(aliceKeyPair.PublicKey));
    candidateList.Value.ShouldContain(ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(bobPubkey)));
    
    // This violates the stated invariant: "Candidate cannot be others' admin"
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L1-50)
```csharp
using AElf.Sdk.CSharp.State;
using AElf.Standards.ACS1;
using AElf.Types;

namespace AElf.Contracts.Election;

public partial class ElectionContractState : ContractState
{
    public BoolState Initialized { get; set; }
    public BoolState VotingEventRegistered { get; set; }

    public SingletonState<Hash> TreasuryHash { get; set; }
    public SingletonState<Hash> WelfareHash { get; set; }
    public SingletonState<Hash> SubsidyHash { get; set; }
    public SingletonState<Hash> FlexibleHash { get; set; }
    public SingletonState<Hash> WelcomeHash { get; set; }

    // Old:Pubkey/New:Address -> ElectorVote
    public MappedState<string, ElectorVote> ElectorVotes { get; set; }

    public MappedState<string, CandidateVote> CandidateVotes { get; set; }

    public MappedState<string, CandidateInformation> CandidateInformationMap { get; set; }

    public Int64State CurrentTermNumber { get; set; }

    public SingletonState<PubkeyList> Candidates { get; set; }

    public SingletonState<DataCenterRankingList> DataCentersRankingList { get; set; }

    public SingletonState<PubkeyList> InitialMiners { get; set; }

    public MappedState<string, bool> BannedPubkeyMap { get; set; }

    /// <summary>
    ///     Vote Id -> Lock Time (seconds)
    /// </summary>
    public MappedState<Hash, long> LockTimeMap { get; set; }

    public MappedState<long, TermSnapshot> Snapshots { get; set; }

    public Int32State MinersCount { get; set; }

    /// <summary>
    ///     Time unit: seconds
    /// </summary>
    public Int64State MinimumLockTime { get; set; }

    /// <summary>
    ///     Time unit: seconds
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L19-57)
```csharp
    public override Empty SetCandidateAdmin(SetCandidateAdminInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.Pubkey), "Pubkey is already banned.");

        // Permission check
        var pubkey = State.InitialPubkeyMap[input.Pubkey] ?? input.Pubkey;
        if (Context.Sender != GetParliamentDefaultAddress())
        {
            if (State.CandidateAdmins[pubkey] == null)
            {
                // If admin is not set before (due to old contract code)
                Assert(Context.Sender == Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Pubkey)),
                    "No permission.");
            }
            else
            {
                var oldCandidateAdmin = State.CandidateAdmins[pubkey];
                Assert(Context.Sender == oldCandidateAdmin, "No permission.");
            }
        }

        State.CandidateAdmins[pubkey] = input.Admin;

        var pubkeyByteString = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(pubkey));

        var newAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[input.Admin] ?? new PubkeyList();
        if (!newAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            newAdminManagedPubkeys.Value.Add(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[input.Admin] = newAdminManagedPubkeys;

        var oldAdminManagedPubkeys = State.ManagedCandidatePubkeysMap[Context.Sender] ?? new PubkeyList();
        if (oldAdminManagedPubkeys.Value.Contains(pubkeyByteString))
            oldAdminManagedPubkeys.Value.Remove(pubkeyByteString);
        State.ManagedCandidatePubkeysMap[Context.Sender] = oldAdminManagedPubkeys;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-119)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[input] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(recoveredPublicKey));
        State.ManagedCandidatePubkeysMap[input] = managedPubkeys;

        LockCandidateNativeToken();

        AddCandidateAsOption(pubkey);

        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-142)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
    {
        var pubkey = input.Pubkey;
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(pubkey);
        var address = Address.FromPublicKey(pubkeyBytes);
        AnnounceElection(pubkeyBytes);
        var admin = input.Admin ?? Context.Sender;
        State.CandidateAdmins[pubkey] = admin;
        var managedPubkeys = State.ManagedCandidatePubkeysMap[admin] ?? new PubkeyList();
        managedPubkeys.Value.Add(ByteString.CopyFrom(pubkeyBytes));
        State.ManagedCandidatePubkeysMap[admin] = managedPubkeys;
        LockCandidateNativeToken();
        AddCandidateAsOption(pubkey);
        if (State.Candidates.Value.Value.Count <= GetValidationDataCenterCount())
        {
            State.DataCentersRankingList.Value.DataCenters.Add(pubkey, 0);
            RegisterCandidateToSubsidyProfitScheme(pubkey);
        }

        State.CandidateSponsorMap[input.Pubkey] = Context.Sender;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-280)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });

        // Update candidate information.
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;

        // Remove candidate public key from the Voting Item options.
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
        var dataCenterList = State.DataCentersRankingList.Value;
        if (dataCenterList.DataCenters.ContainsKey(pubkey))
        {
            dataCenterList.DataCenters[pubkey] = 0;
            UpdateDataCenterAfterMemberVoteAmountChanged(dataCenterList, pubkey, true);
            State.DataCentersRankingList.Value = dataCenterList;
        }

        var managedCandidatePubkey = State.ManagedCandidatePubkeysMap[Context.Sender];
        managedCandidatePubkey.Value.Remove(ByteString.CopyFrom(pubkeyBytes));
        if (managedCandidatePubkey.Value.Any())
            State.ManagedCandidatePubkeysMap[Context.Sender] = managedCandidatePubkey;
        else
            State.ManagedCandidatePubkeysMap.Remove(Context.Sender);

        State.CandidateSponsorMap.Remove(pubkey);

        return new Empty();
    }
```

**File:** protobuf/election_contract.proto (L36-39)
```text
    rpc AnnounceElection (aelf.Address) returns (google.protobuf.Empty) {
    }
    rpc AnnounceElectionFor (AnnounceElectionForInput) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L601-629)
```csharp
    public override Empty SetProfitsReceiver(SetProfitsReceiverInput input)
    {
        if (State.ElectionContract.Value == null)
            State.ElectionContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        var pubkey = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.Pubkey));
        
        var admin = State.ElectionContract.GetCandidateAdmin.Call(new StringValue {Value = input.Pubkey});
        Assert(Context.Sender == admin , "No permission.");
        
        var candidateList = State.ElectionContract.GetCandidates.Call(new Empty());
        Assert(candidateList.Value.Contains(pubkey),"Pubkey is not a candidate.");

        var previousProfitsReceiver = State.ProfitsReceiverMap[input.Pubkey];
        //Set same profits receiver address.
        if (input.ProfitsReceiverAddress == previousProfitsReceiver)
        {
            return new Empty();
        }
        State.ProfitsReceiverMap[input.Pubkey] = input.ProfitsReceiverAddress;
        State.ElectionContract.SetProfitsReceiver.Send(new AElf.Contracts.Election.SetProfitsReceiverInput
        {
            CandidatePubkey = input.Pubkey,
            ReceiverAddress = input.ProfitsReceiverAddress,
            PreviousReceiverAddress = previousProfitsReceiver ?? new Address()
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-257)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);

        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));

        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }

        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }

        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }

        //     For CandidateVotes and CandidateInformation, just replace value of origin pubkey.
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }

        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }

        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;

        ReplaceCandidateProfitsReceiver(input.OldPubkey, input.NewPubkey);
        
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L427-430)
```csharp
    public override PubkeyList GetManagedPubkeys(Address input)
    {
        return State.ManagedCandidatePubkeysMap[input];
    }
```
