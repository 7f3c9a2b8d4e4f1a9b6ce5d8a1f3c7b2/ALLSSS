import json
import os

from decouple import config

MAX_REPO = 30
SOURCE_REPO = "AElfProject/AElf"
REPO_NAME = "aelf"
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
        """Convert run number to a cyclic index between 1 and max_index"""
        return (int(run_number) - 1) % max_index + 1


if run_number == "0":
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
        # Convert to cyclic index (1-100)
        run_index = get_cyclic_index(run_number, MAX_REPO)
        # Format the URL with leading zeros
        repo_number = f"{run_index:03d}"
        BASE_URL = f"https://deepwiki.com/grass-dev-pa/{REPO_NAME}-{repo_number}"

scope_files = [
        "contract/AElf.Contracts.Association/Association.cs",
        "contract/AElf.Contracts.Association/AssociationConstants.cs",
        "contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Association/AssociationReferenceState.cs",
        "contract/AElf.Contracts.Association/AssociationState.cs",
        "contract/AElf.Contracts.Association/Association_Extensions.cs",
        "contract/AElf.Contracts.Association/Association_Helper.cs",
        "contract/AElf.Contracts.Association/OrganizationMemberList.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationContract.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationReferenceState.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationState.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_CacheFileds.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusCommandProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/ICommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/IHeaderInformationValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ContractsReferences.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLighterRound.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLogs.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContractState.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_Constants.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainReferenceState.cs",
        "contract/AElf.Contracts.Economic/EconomicContract.cs",
        "contract/AElf.Contracts.Economic/EconomicContractConstants.cs",
        "contract/AElf.Contracts.Economic/EconomicContractState.cs",
        "contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Election/ElectionContractConstants.cs",
        "contract/AElf.Contracts.Election/ElectionContractReferenceState.cs",
        "contract/AElf.Contracts.Election/ElectionContractState.cs",
        "contract/AElf.Contracts.Election/ElectionContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Election/ElectionContract_Candidate.cs",
        "contract/AElf.Contracts.Election/ElectionContract_Elector.cs",
        "contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs",
        "contract/AElf.Contracts.Election/TimestampHelper.cs",
        "contract/AElf.Contracts.Election/ViewMethods.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZero.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZeroReferenceState.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZeroState.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractConstants.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractReferenceState.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractState.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractState_ChargeFee.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_CacheFileds.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Views.cs",
        "contract/AElf.Contracts.NFT/NFTContractConstants.cs",
        "contract/AElf.Contracts.NFT/NFTContractReferenceState.cs",
        "contract/AElf.Contracts.NFT/NFTContractState.cs",
        "contract/AElf.Contracts.NFT/NFTContract_ACS1.cs",
        "contract/AElf.Contracts.NFT/NFTContract_Create.cs",
        "contract/AElf.Contracts.NFT/NFTContract_Helpers.cs",
        "contract/AElf.Contracts.NFT/NFTContract_UseChain.cs",
        "contract/AElf.Contracts.NFT/NFTContract_View.cs",
        "contract/AElf.Contracts.Parliament/Parliament.cs",
        "contract/AElf.Contracts.Parliament/ParliamentConstants.cs",
        "contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Parliament/ParliamentState.cs",
        "contract/AElf.Contracts.Parliament/Parliament_Constants.cs",
        "contract/AElf.Contracts.Parliament/Parliament_Helper.cs",
        "contract/AElf.Contracts.Profit/ContractsReferences.cs",
        "contract/AElf.Contracts.Profit/Models/RemovedDetails.cs",
        "contract/AElf.Contracts.Profit/ProfitContract.cs",
        "contract/AElf.Contracts.Profit/ProfitContractConstants.cs",
        "contract/AElf.Contracts.Profit/ProfitContractState.cs",
        "contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Profit/ViewMethods.cs",
        "contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs",
        "contract/AElf.Contracts.Referendum/Referendum.cs",
        "contract/AElf.Contracts.Referendum/ReferendumConstants.cs",
        "contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Referendum/ReferendumState.cs",
        "contract/AElf.Contracts.Referendum/Referendum_Helper.cs",
        "contract/AElf.Contracts.TokenConverter/BancorHelper.cs",
        "contract/AElf.Contracts.TokenConverter/InvalidValueException.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConverterContractState.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConverterContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.TokenHolder/ContractsReferences.cs",
        "contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs",
        "contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs",
        "contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Treasury/ContractsReferences.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContract.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContractConstants.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContractState.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Vote/ContractsReferences.cs",
        "contract/AElf.Contracts.Vote/ViewMethods.cs",
        "contract/AElf.Contracts.Vote/VoteContract.cs",
        "contract/AElf.Contracts.Vote/VoteContractConstants.cs",
        "contract/AElf.Contracts.Vote/VoteContractState.cs",
        "contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Vote/VoteExtensions.cs",

        "contract/AElf.Contracts.Association/Association.cs",
        "contract/AElf.Contracts.Association/AssociationConstants.cs",
        "contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Association/AssociationReferenceState.cs",
        "contract/AElf.Contracts.Association/AssociationState.cs",
        "contract/AElf.Contracts.Association/Association_Extensions.cs",
        "contract/AElf.Contracts.Association/Association_Helper.cs",
        "contract/AElf.Contracts.Association/OrganizationMemberList.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationContract.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationReferenceState.cs",
        "contract/AElf.Contracts.Configuration/ConfigurationState.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_CacheFileds.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusCommandProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/ICommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/IHeaderInformationValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/ContractsReferences.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLighterRound.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLogs.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs",
        "contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContractState.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_Constants.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs",
        "contract/AElf.Contracts.CrossChain/CrossChainReferenceState.cs",
        "contract/AElf.Contracts.Economic/EconomicContract.cs",
        "contract/AElf.Contracts.Economic/EconomicContractConstants.cs",
        "contract/AElf.Contracts.Economic/EconomicContractState.cs",
        "contract/AElf.Contracts.Economic/EconomicContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Election/ElectionContractConstants.cs",
        "contract/AElf.Contracts.Election/ElectionContractReferenceState.cs",
        "contract/AElf.Contracts.Election/ElectionContractState.cs",
        "contract/AElf.Contracts.Election/ElectionContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Election/ElectionContract_Candidate.cs",
        "contract/AElf.Contracts.Election/ElectionContract_Elector.cs",
        "contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs",
        "contract/AElf.Contracts.Election/TimestampHelper.cs",
        "contract/AElf.Contracts.Election/ViewMethods.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZero.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZeroReferenceState.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZeroState.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs",
        "contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractConstants.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractReferenceState.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractState.cs",
        "contract/AElf.Contracts.MultiToken/TokenContractState_ChargeFee.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_CacheFileds.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Method_Authorization.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs",
        "contract/AElf.Contracts.MultiToken/TokenContract_Views.cs",
        "contract/AElf.Contracts.NFT/NFTContractConstants.cs",
        "contract/AElf.Contracts.NFT/NFTContractReferenceState.cs",
        "contract/AElf.Contracts.NFT/NFTContractState.cs",
        "contract/AElf.Contracts.NFT/NFTContract_ACS1.cs",
        "contract/AElf.Contracts.NFT/NFTContract_Create.cs",
        "contract/AElf.Contracts.NFT/NFTContract_Helpers.cs",
        "contract/AElf.Contracts.NFT/NFTContract_UseChain.cs",
        "contract/AElf.Contracts.NFT/NFTContract_View.cs",
        "contract/AElf.Contracts.Parliament/Parliament.cs",
        "contract/AElf.Contracts.Parliament/ParliamentConstants.cs",
        "contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Parliament/ParliamentState.cs",
        "contract/AElf.Contracts.Parliament/Parliament_Constants.cs",
        "contract/AElf.Contracts.Parliament/Parliament_Helper.cs",
        "contract/AElf.Contracts.Profit/ContractsReferences.cs",
        "contract/AElf.Contracts.Profit/Models/RemovedDetails.cs",
        "contract/AElf.Contracts.Profit/ProfitContract.cs",
        "contract/AElf.Contracts.Profit/ProfitContractConstants.cs",
        "contract/AElf.Contracts.Profit/ProfitContractState.cs",
        "contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Profit/ViewMethods.cs",
        "contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs",
        "contract/AElf.Contracts.Referendum/Referendum.cs",
        "contract/AElf.Contracts.Referendum/ReferendumConstants.cs",
        "contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Referendum/ReferendumState.cs",
        "contract/AElf.Contracts.Referendum/Referendum_Helper.cs",
        "contract/AElf.Contracts.TokenConverter/BancorHelper.cs",
        "contract/AElf.Contracts.TokenConverter/InvalidValueException.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConverterContractState.cs",
        "contract/AElf.Contracts.TokenConverter/TokenConverterContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.TokenHolder/ContractsReferences.cs",
        "contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs",
        "contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs",
        "contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Treasury/ContractsReferences.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContract.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContractConstants.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContractState.cs",
        "contract/AElf.Contracts.Treasury/TreasuryContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Vote/ContractsReferences.cs",
        "contract/AElf.Contracts.Vote/ViewMethods.cs",
        "contract/AElf.Contracts.Vote/VoteContract.cs",
        "contract/AElf.Contracts.Vote/VoteContractConstants.cs",
        "contract/AElf.Contracts.Vote/VoteContractState.cs",
        "contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs",
        "contract/AElf.Contracts.Vote/VoteExtensions.cs",


]


def question_generator(target_file: str) -> str:
        """
        Generates targeted security audit questions for a specific AElf smart contract file.

        Args:
            target_file: The specific file path to focus question generation on.
                        (e.g., "contract/AElf.Contracts.MultiToken/TokenContract.cs")

        Returns:
            A formatted prompt string for generating security questions.
        """
        prompt = f"""
# **Generate 150+ Targeted Security Audit Questions for AElf Core Smart Contracts (C#)**

## **Context**

The target project is **AElf**'s C# smart-contract suite that runs on the AElf blockchain. Major domains:
- **Consensus (AEDPoS)**: round generation, miner lists, time slots, secret sharing, consensus command generation, maximum miner count and emergency behaviours.
- **Governance & Authorization**: Parliament, Referendum, Association multi-sig, Configuration, Genesis (BasicContractZero) method fee provider, organization thresholds, proposal lifecycle, proposer whitelists.
- **Economics & Treasury**: Economic parameters, Treasury reserves, Profit distributions, TokenHolder dividends, method-fee collection and distribution.
- **Tokens & Assets**: MultiToken (fungible/NFT issuance, mint/burn, allowances), NFT contract, TokenConverter (Bancor-based swap/price curve), TokenHolder staking/lockers.
- **Cross-Chain**: CrossChain indexing/verification, side-chain block header validation, merkle proofs, irreversible block height handling.
- **Elections & Voting**: Election and Vote contracts, candidate management, elector vote locking and reward settlement.

## **Scope**

**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`

Questions must be generated from `{target_file}` only. If you cannot reach 150 questions from this file, produce as many high-quality, file-specific questions as possible. If the file exceeds ~1000 lines, go up to 300+ questions. Do not return empty results.

## **Core AElf Components** (for reference only)

```python
core_components = [
    "contract/AElf.Contracts.Consensus.AEDPoS/*",
    "contract/AElf.Contracts.CrossChain/*",
    "contract/AElf.Contracts.Parliament/*",
    "contract/AElf.Contracts.Referendum/*",
    "contract/AElf.Contracts.Association/*",
    "contract/AElf.Contracts.Configuration/*",
    "contract/AElf.Contracts.Economic/*",
    "contract/AElf.Contracts.Treasury/*",
    "contract/AElf.Contracts.Profit/*",
    "contract/AElf.Contracts.Vote/*",
    "contract/AElf.Contracts.Election/*",
    "contract/AElf.Contracts.MultiToken/*",
    "contract/AElf.Contracts.NFT/*",
    "contract/AElf.Contracts.TokenConverter/*",
    "contract/AElf.Contracts.TokenHolder/*",
    "contract/AElf.Contracts.Genesis/*",
]
```

## **Critical Invariant Areas**

- **Auth & Governance**: proposal creation/approval thresholds, organization auth (Parliament/Association/Referendum), proposer whitelist checks, method fee provider auth, token whitelist/blacklist rules.
- **Consensus Safety**: round updates, miner list transitions, time-slot validation, consensus command correctness, LIB height calculations, secret-sharing flows, punishment and dividends distribution.
- **Token & Supply Integrity**: mint/burn constraints, allowance/approval checks, fee deductions, lock/unlock flows, NFT issuance uniqueness, delegation logic.
- **Economic & Treasury Accounting**: Profit/Treasury share calculations, donation/release mechanics, dividend pool distribution, TokenHolder reward math.
- **Cross-Chain Verification**: merkle proof validation, index heights, parent-chain info integrity, side-chain creation/indexing security, re-org handling.
- **Converter & Pricing**: Bancor formula correctness, reserve balances, price slippage limits, insufficient reserve handling.

## **In-Scope Vulnerability Categories**

- Authorization/governance bypass enabling unauthorized proposal execution, token mint/burn, fee changes, or config updates.
- Consensus or cross-chain validation flaws enabling fake headers, incorrect round transitions, or mining schedule corruption.
- Accounting/math errors causing supply inflation/deflation, dividend misallocation, or fee leakage.
- Lock/vesting/approval bugs allowing premature withdrawals or denial of rewards.
- Pricing or reserve-handling mistakes in TokenConverter leading to underpriced swaps or pool depletion.
- DOS vectors that freeze governance, consensus progress, cross-chain indexing, or token operations through valid calls.

## **Question Format Template**

Each question MUST follow this Python list format:

```python
questions = [
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific exploit scenario with preconditions, violated invariant, attacker action, and concrete impact? (High)",
]
```

## **Output Requirements**

Generate questions focusing EXCLUSIVELY on `{target_file}` that:
- Reference real functions/methods/logic blocks in `{target_file}`
- Include concrete exploit paths, not generic checks
- Tie each question to math logic, business logic, or invariant breaks
- Prioritize questions likely to result in **valid vulnerabilities**
- Avoid low-signal or non-exploitable questions
- Include severity `(Critical/High/Medium/Low)` in each question
- Use exact Python list format

## **Target Question Count**

- Small files: 80-150 questions when possible
- Medium files: 150+ questions
- Very large files (>1000 lines): 300+ questions
- If code size limits quantity, output as many quality questions as possible

Begin generating questions for `{target_file}` now.
"""
        return prompt


def validation_format(report: str) -> str:
        """
        Generates a comprehensive validation prompt for AElf smart-contract security claims.

        Args:
            report: A security vulnerability report to validate

        Returns:
            A formatted validation prompt string for strict technical scrutiny
        """
        prompt = f"""
You are an **Elite AElf Smart Contract Security Judge** with deep expertise in C# contracts, AElf runtime semantics, AEDPoS consensus, governance organizations (Parliament/Referendum/Association), MultiToken/NFT supply rules, TokenConverter pricing, Profit/Treasury distributions, cross-chain indexing, and election/vote mechanics.

Your ONLY task is **ruthless technical validation** of the claim below.

Trusted roles: genesis method-fee provider, organization controllers (Parliament/Association/Referendum), consensus system contracts; assume they are honest unless the claim is about mis-scoped privileges.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **AELF VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if **ANY** apply.

Before a vulnerability is valid it must have BOTH:
1) concrete impact to protocol/users/funds/state integrity
2) feasible likelihood / trigger path

If it cannot be triggered realistically, reject (except directly reachable invariant breaks).

Return MUST be either:
- the original report (if valid)
- `#NoVulnerability` (if invalid)

Any vuln without valid protocol impact is invalid.
Attacker self-harm-only scenarios are invalid.

#### **A. Scope Violations**
- ❌ Affects files not in production source scope
- ❌ Targets tests, mocks, examples, scripts, docs, comments, style-only issues
- ❌ Off-chain tooling instead of on-chain contract logic

**In-Scope AElf smart contract files**
```python
scope_files = {scope_files}
```

#### **B. Threat Model Violations**
- ❌ Requires compromised genesis/organization/consensus keys
- ❌ Assumes consensus break or chain reorg control beyond protocol rules
- ❌ Breaks cryptographic primitives or AElf VM internals
- ❌ Relies on phishing/social engineering/wallet compromise
- ❌ Pure network-layer attacks (DDoS/BGP/DNS/etc.)

#### **C. Non-Security / Known Issues**
- ❌ Already fixed/known with no live exploit path
- ❌ Gas/performance/style tweaks without security impact
- ❌ Logging/events/doc-only issues
- ❌ Theoretical concerns with no executable path/impact

#### **D. Invalid Exploit Scenarios**
- ❌ Impossible inputs or unreachable internal-only methods
- ❌ Requires privileges attacker cannot obtain
- ❌ Needs self-loss with no protocol invariant break
- ❌ No measurable impact on balances, ownership, authorization, or availability

### **PHASE 2: AELF DEEP CODE VALIDATION**

#### **Step 1: Trace Complete Execution Path**
Reconstruct:
1. Entry point (public method on the contract)
2. Full call chain
3. Pre-state (organization thresholds, proposal status, miner list/round info, token balances/allowances/locks, reserve balances, profit/treasury pools, cross-chain index heights)
4. State transitions at each step
5. Existing guards (authority checks, proposal approvals, fee deduction, time/height checks, supply bounds, signature/proof validation, duplicate protection)
6. Final post-state and violated invariant

If any step is missing or unreachable, return `#NoVulnerability`.

#### **Step 2: Evidence Requirements**
A valid report must provide:
- Exact file path(s) and relevant code references
- Concrete vulnerable logic and bypass explanation
- Triggerable transaction flow with realistic attacker actions
- Why protections do not stop it
- Quantified impact (fund loss/supply inflation, unauthorized config/proposal execution, cross-chain spoofing, governance capture)

Red flags -> invalid:
- “might be vulnerable” without exploit sequence
- no clear invariant broken
- no impact beyond revert/no-op
- assumptions that contradict AElf VM and contract semantics

#### **Step 3: AELF-Specific Validity Checks**
Validate against these domains:

1. **Governance & Auth**
- Parliament/Association/Referendum thresholds, proposer whitelist, organization hashes, proposal lifetime, method-fee provider authority.

2. **Consensus**
- Round transitions, miner schedule, time-slot validation, maximum miners, LIB height, secret sharing, dividends pool handling.

3. **Tokens & Supply**
- MultiToken mint/burn rules, allowances, fee deductions, lock/unlock, NFT uniqueness, delegation/approval paths.

4. **Economics & Rewards**
- Treasury/Profit/TokenHolder calculations, donation/release logic, share/distribution math, vote staking/lock durations.

5. **Cross-Chain**
- Merkle proof validation, side-chain index heights, parent-chain info retrieval, irreversible block constraints.

6. **Pricing (TokenConverter)**
- Bancor formula, reserve ratio bounds, slippage controls, insufficient reserve handling, price rounding.

### **PHASE 3: IMPACT + LIKELIHOOD JUDGMENT**

Valid ONLY if BOTH are true:

1. **Impact**
- Fund loss/misdirection, supply inflation/deflation, reward misallocation
- Unauthorized governance/config/fee changes
- Consensus or cross-chain integrity break
- High-confidence DoS of governance/consensus/token operations

2. **Likelihood**
- Executable by untrusted actor via public methods
- Realistic preconditions
- Reproducible under AElf runtime rules

If either fails -> `#NoVulnerability`.

### **DECISION OUTPUT (STRICT)**
           
---            
            
**AUDIT REPORT FORMAT** (if vulnerability found):            
            
Audit Report            
            
## Title 
The Title Of the Report 

## Summary
A short summary of the issue, keep it brief.

## Finding Description
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.

Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.

## Impact Explanation
Elaborate on why you've chosen a particular impact assessment.

## Likelihood Explanation
Explain how likely this is to occur and why.


## Recommendation
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.


## Proof of Concept
Note very important the poc must have a valid test that runs just one function that proove the vuln 
  **Remember**: False positives harm credibility more than missed findings. Assume claims are invalid until overwhelming evidence proves otherwise.    
    
**Now perform STRICT validation of the claim above.**    
    
**Output ONLY:**    
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format    
- `#NoVulnerability found for this question.` (if **any** check fails) very important    
- Note if u cant validate the claim or dont understand just send #NoVulnerability    
- Only show full report when u know this is actually and truly a  valid vulnerability 
"""
        return prompt


def audit_format(security_question: str) -> str:
        """
        Generate a comprehensive security audit prompt for the AElf smart-contract suite.

        Args:
            security_question: The specific security concern to investigate

        Returns:
            A detailed audit prompt with strict validation requirements
        """

        prompt = f"""# AELF SMART CONTRACT SECURITY AUDIT PROMPT

## Security Question to Investigate:
{security_question}

## Codebase Context

### Core Components
You are auditing **AElf** C# contracts that include:
- **Consensus (AEDPoS)**: round generation, miner lists, time slots, consensus command generation, dividends pool.
- **Governance**: Parliament, Association (multi-sig), Referendum, Configuration, Genesis method fee provider.
- **Economics & Rewards**: Economic initialization, Treasury, Profit, TokenHolder staking/dividends.
- **Tokens & Assets**: MultiToken (fungible + NFT), NFT contract, TokenConverter (Bancor pricing), TokenHolder locking.
- **Cross-Chain**: CrossChain indexing/verification, parent/side-chain info, irreversible block heights.
- **Elections & Voting**: Election and Vote contracts managing candidates, electors, vote locks.

## CRITICAL INVARIANTS (Must Hold at All Times)

1. **Authorization & Governance**
- Organization thresholds, proposer whitelist checks, proposal lifetime/expiration, correct organization hash resolution, method-fee provider authority.

2. **Consensus & Cross-Chain**
- Correct round transitions and time-slot validation, miner schedule integrity, LIB height rules, cross-chain proof verification and index heights.

3. **Token Supply & Fees**
- Mint/burn limits, allowance/approval enforcement, lock/unlock correctness, fee deduction paths, NFT uniqueness and ownership checks.

4. **Economics & Treasury**
- Profit/Treasury/TokenHolder share calculations, donation/release logic, dividend distribution and settlement accuracy.

5. **Pricing & Reserves**
- Bancor reserve ratio bounds, swap price calculation, slippage controls, reserve depletion protection.

## ATTACK SURFACES

### 1. Governance & Proposals
- Parliament/Association/Referendum proposal creation, approval thresholds, release, and execution paths; organization updates; proposer whitelist logic.

### 2. Consensus & Cross-Chain
- Round/term update functions, time-slot validation, miner list mutations, consensus command generation, parent/side-chain indexing, merkle proof verification.

### 3. Token & Fee Paths
- MultiToken mint/burn/transfer/lock, method-fee deduction, NFT mint/transfer, token approvals, TokenHolder deposits/withdrawals.

### 4. Economics & Distribution
- Treasury donations/releases, Profit scheme creation/distribution, TokenHolder dividends, election reward allocations.

### 5. Pricing & Conversion
- TokenConverter swap paths, reserve updates, virtual balances, price precision/rounding.

## VULNERABILITY VALIDATION REQUIREMENTS

A finding is ONLY valid if it passes ALL checks:

### Impact Assessment (Must be Concrete)
- [ ] **Direct Fund Impact**: theft, inflation/deflation, reward misallocation
- [ ] **Auth/Governance Impact**: unauthorized proposal execution/config change
- [ ] **Consensus/Cross-Chain Integrity**: fake header/proof acceptance, invalid round transitions
- [ ] **Operational Impact**: DoS of governance/consensus/token/cross-chain flows

### Likelihood Assessment (Must be Practical)
- [ ] **Reachable Entry Point**: starts from real public method
- [ ] **Feasible Preconditions**: attacker capabilities realistic
- [ ] **Execution Practicality**: steps executable under AElf contract semantics
- [ ] **Economic Rationality**: exploit cost reasonable

### Validation Checklist
Before reporting a vulnerability, verify:
1. [ ] Exact file/function/line references
2. [ ] Root cause clearly identified
3. [ ] End-to-end exploitation path
4. [ ] Existing checks shown insufficient
5. [ ] Realistic attack parameters and sequence
6. [ ] Concrete impact quantification
7. [ ] No reliance on trusted role compromise beyond claim
8. [ ] No contradiction with AElf VM/execution model

## AUDIT REPORT FORMAT

If a valid vulnerability is found (passes all checks), output this EXACT structure:

### Title
[Concise vulnerability title]

### Summary
[2-3 sentence summary of issue and consequence]

### Finding Description
[Technical details including:
- exact code location(s)
- root cause
- why protections fail
- relevant execution path]

### Impact Explanation
[Concrete impact:
- what harm occurs
- quantified value/protocol damage
- who is affected
- severity justification]

### Likelihood Explanation
[Realistic exploitability:
- attacker capabilities
- attack complexity
- feasibility conditions
- detection/operational constraints
- probability reasoning]

### Recommendation
[Actionable fix:
- exact code-level mitigation
- invariant checks to add
- test cases to prevent regression]

### Proof of Concept
[Reproducible exploit sequence:
- required initial state
- transaction steps
- expected vs actual result
- clear success condition]

## STRICT OUTPUT REQUIREMENT

After investigation:

IF a vulnerability passes ALL validation gates with clear evidence:
-> Output the complete audit report in the format above

IF no valid vulnerability exists:
-> Output exactly: "#NoVulnerability found for this question."

Do not output anything else.

## Investigation Guidelines

1. Start from entry functions reachable by untrusted users
2. Trace full state transitions and all side effects
3. Check math/rounding/bounds and extreme values
4. Check cross-contract flows (consensus <-> governance <-> token <-> profit/treasury <-> converter <-> cross-chain)
5. Validate authority/time/height checks end-to-end
6. Reject speculative findings lacking concrete exploit path

Remember: only report vulnerabilities with both valid impact and valid likelihood.

Begin investigation of: {security_question}

"""

        return prompt


def scan_format(report: str) -> str:
        """
        Generate a cross-protocol analog vulnerability scanning prompt for the AElf contracts.

        Args:
            report: A vulnerability report from another protocol/project

        Returns:
            A strict scan prompt string that looks for equivalent vulnerability classes in AElf
        """

        prompt = f"""# AELF CROSS-PROTOCOL ANALOG SCAN PROMPT

## External Report To Map Into AElf
{report}

## Objective
You are a senior protocol security researcher. Analyze the external report above and determine whether the **same vulnerability class** (not necessarily exact code pattern) can occur anywhere in AElf smart contracts.

You must scan AElf contract logic across modules, execution paths, state transitions, and invariants.

## AElf Modules To Scan

- `contract/AElf.Contracts.Consensus.AEDPoS/*`
- `contract/AElf.Contracts.CrossChain/*`
- `contract/AElf.Contracts.Parliament/*`
- `contract/AElf.Contracts.Association/*`
- `contract/AElf.Contracts.Referendum/*`
- `contract/AElf.Contracts.Configuration/*`
- `contract/AElf.Contracts.Genesis/*`
- `contract/AElf.Contracts.Election/*`
- `contract/AElf.Contracts.Vote/*`
- `contract/AElf.Contracts.MultiToken/*`
- `contract/AElf.Contracts.NFT/*`
- `contract/AElf.Contracts.TokenConverter/*`
- `contract/AElf.Contracts.Treasury/*`
- `contract/AElf.Contracts.Profit/*`
- `contract/AElf.Contracts.TokenHolder/*`

## Core Scan Method

1. **Classify the external vuln type**
- governance/authorization bypass
- consensus or cross-chain validation flaw
- token supply/allowance/lock/accounting error
- pricing/reserve miscalculation (TokenConverter)
- reward/treasury/profit distribution bug
- denial of service via valid calls (governance, consensus, cross-chain, token operations)

2. **Map to AElf analog surfaces**
- Identify equivalent trust boundaries and data-flow points across modules
- Consider proposal-based execution (Parliament/Association/Referendum), consensus time-slot updates, token mint/burn/transfer/lock flows, Bancor pricing, dividend distribution, cross-chain proof verification
- Check cross-module interactions (e.g., proposal executes token mint; consensus uses economic data; cross-chain indexing updates token states)

3. **Trace full exploitability path**
- Real entry point (public contract methods)
- Preconditions attacker can realistically satisfy
- Step-by-step transition chain
- Why current checks fail
- Final broken invariant

4. **Validate impact + likelihood strictly**
- Must have concrete protocol impact
- Must have realistic trigger path
- No speculative or theoretical-only claims

## Critical Invariants To Test During Scan

- Governance thresholds/proposal lifetimes/organization hashes respected
- AEDPoS round/time-slot/miner list integrity maintained
- Token mint/burn/transfer/lock rules and fee deductions enforced
- Profit/Treasury/TokenHolder distributions correct and bounded
- Cross-chain proofs/irreversible height checks valid
- TokenConverter reserve ratio, price calculation, and slippage protections enforced

## Disqualification Rules (Immediate #NoVulnerability)

Reject if ANY apply:

- Not reproducible through AElf public contract methods
- Requires compromised genesis/organization/consensus keys
- Depends on impossible AElf execution assumptions
- Only causes self-harm or non-protocol impact
- No concrete impact on funds, ownership, authorization, or critical availability
- Impact exists but no realistic likelihood
- Likelihood exists but no valid impact

## Required Decision Standard

A vulnerability is valid ONLY if BOTH are true:

1. **Valid Impact**
- Fund theft/drain or supply/fee misrouting
- Unauthorized governance/config/proposal execution
- Consensus/cross-chain integrity break
- Pricing/accounting corruption in TokenConverter/Treasury/Profit
- High-confidence protocol DoS via valid calls

2. **Valid Likelihood**
- Reachable by untrusted actor
- Feasible preconditions
- Executable sequence under AElf rules
- Not blocked by existing checks

If either fails, it is invalid.

## Output Format (Strict)

If a valid analog vulnerability is found in AElf, output full report in this exact structure:

### Title
[Concise vulnerability title]

### Summary
[2-3 sentence summary of mapped vulnerability and impact]

### Finding Description
[Detailed technical mapping from external report type to AElf:
- exact file/function/line references
- root cause in AElf
- exploit path and why protections fail]

### Impact Explanation
[Concrete AElf impact and severity justification]

### Likelihood Explanation
[Realistic exploit feasibility in AElf context]

### Recommendation
[Specific code-level mitigation for AElf]

### Proof of Concept
[Reproducible AElf exploit steps with realistic state/inputs]

If no valid analog vulnerability is found, output exactly:
`#NoVulnerability found for this question.`

Do not output anything else.

## Additional Guidance

- Use the external report as a vulnerability-class hint, not as proof.
- Confirm with AElf-specific code logic only.
- Prefer false-negative over false-positive.
- A claim without executable exploit chain is invalid.

Begin deep analog scan now.

"""

        return prompt

