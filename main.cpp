
#include "cryptonote_core/blockchain.h"
#include "common/base58.h"
#include "crypto/crypto-ops.h"
#include "crypto/hash.h"

#include "src/tools.h"
#include "src/MicroCore.h"
// Converts crypto::hash into crypto::secret_key or crypto::public_key
template <typename T>
T get_key_from_hash(crypto::hash &in_hash)
{
	T *key;
	key = reinterpret_cast<T *>(&in_hash);
	return *key;
}

namespace epee
{
unsigned int g_test_dbg_lock_sleep = 0;
}

int main()
{
	// Put here your private spendable key!
	std::string str_spend_key = "0e87070a67aeb0d4faae19581da9e38730435c13840bf0199be1d590576a350d";
	// cryptonote::network_type nettype = cryptonote::MAINNET;
	cryptonote::network_type nettype = cryptonote::TESTNET;

	crypto::public_key public_spend_key;

	// Convert hex string to binary data
	cryptonote::blobdata blob;
	epee::string_tools::parse_hexstr_to_binbuff(str_spend_key, blob);
	crypto::secret_key sc = *reinterpret_cast<const crypto::secret_key *>(blob.data());
	// std::cout << "Private spend key : " << sc << std::endl;

	// Generate public spend key based on the private spend key (sc)
	crypto::secret_key_to_public_key(sc, public_spend_key);

	// std::cout << "Public spend key : "  << public_spend_key  << std::endl;

	crypto::hash hash_of_private_spend_key;

	crypto::cn_fast_hash(&sc, sizeof(hash_of_private_spend_key), hash_of_private_spend_key);

	crypto::secret_key private_view_key;
	crypto::public_key public_view_key;

	crypto::generate_keys(public_view_key, private_view_key, get_key_from_hash<crypto::secret_key>(hash_of_private_spend_key), true);

	// std::cout << "\n" << "Private view key : "  << private_view_key << std::endl;
	// std::cout << "Public view key  : "  << public_view_key  << std::endl;

	cryptonote::account_public_address address{public_spend_key, public_view_key};
	std::string public_address;

	public_address = cryptonote::get_account_address_as_str(nettype, false, address);
	// std::cout << "Monero Address:" << public_address << std::endl;

	//******************************************************************************************************************************************//

	// change timezone to Universtal time zone char old_tz[128];
	const char *tz_org = getenv("TZ");
	char old_tz[128];

	if (tz_org)
		strcpy(old_tz, tz_org);

	// set new timezone
	std::string tz = "TZ=Coordinated Universal Time";
	putenv(const_cast<char *>(tz.c_str()));
	tzset(); // Initialize timezone data

	// set monero log output level
	uint32_t log_level = 0;
	mlog_configure("", true);

	// enable basic monero log output
	// uint32_t log_level = 0;
	// epee::log_space::get_set_log_detalisation_level(true, log_level);
	// epee::log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL);

	boost::filesystem::path blockchain_path;
	std::string bc_path_opt = "/home/luca/Monero/stagenet/node_02/stagenet/lmdb";

	if (!xmreg::get_blockchain_path(bc_path_opt, blockchain_path, nettype))
	{
		std::cerr << "Error getting blockchain path." << std::endl;
		return 1;
	}

	// create instance of our MicroCore
	// and make pointer to the Blockchain
	xmreg::MicroCore mcore;
	cryptonote::Blockchain *core_storage;

	// initialize mcore and core_storage
	if (!xmreg::init_blockchain(blockchain_path.string(),
								mcore, core_storage, nettype))
	{
		std::cerr << "Error accessing blockchain." << std::endl;
		return 1;
	}
	std::cout << "Blockchain path: {:s}\t" << blockchain_path << std::endl;
	std::cout << "blockchain height:\t" << core_storage->get_current_blockchain_height() <<std::endl;



	return 0;
}