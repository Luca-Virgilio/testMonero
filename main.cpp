
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
	// // Put here your private spendable key!
	// std::string str_spend_key = "0e87070a67aeb0d4faae19581da9e38730435c13840bf0199be1d590576a350d";
	// // cryptonote::network_type nettype = cryptonote::MAINNET;

	// crypto::public_key public_spend_key;

	// // Convert hex string to binary data
	// cryptonote::blobdata blob;
	// epee::string_tools::parse_hexstr_to_binbuff(str_spend_key, blob);
	// crypto::secret_key sc = *reinterpret_cast<const crypto::secret_key *>(blob.data());
	// // std::cout << "Private spend key : " << sc << std::endl;

	// // Generate public spend key based on the private spend key (sc)
	// crypto::secret_key_to_public_key(sc, public_spend_key);

	// // std::cout << "Public spend key : "  << public_spend_key  << std::endl;

	// crypto::hash hash_of_private_spend_key;

	// crypto::cn_fast_hash(&sc, sizeof(hash_of_private_spend_key), hash_of_private_spend_key);

	// crypto::secret_key private_view_key;
	// crypto::public_key public_view_key;

	// crypto::generate_keys(public_view_key, private_view_key, get_key_from_hash<crypto::secret_key>(hash_of_private_spend_key), true);

	// // std::cout << "\n" << "Private view key : "  << private_view_key << std::endl;
	// // std::cout << "Public view key  : "  << public_view_key  << std::endl;

	// cryptonote::account_public_address address{public_spend_key, public_view_key};
	// std::string public_address;

	// public_address = cryptonote::get_account_address_as_str(nettype, false, address);
	// // std::cout << "Monero Address:" << public_address << std::endl;

	//******************************************************************************************************************************************//
	cryptonote::network_type nettype = cryptonote::STAGENET;

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
	uint64_t height = core_storage->get_current_blockchain_height();
	std::cout << "blockchain height:\t" << height << std::endl;

	// parse string representing given monero address
	cryptonote::address_parse_info address_info;
	std::string address_str = "59y5wNUMuKgZ9xgwGdY2Tb1bmu6WLrjvDcoC2T2Fxmek9VQ2ASc2hrVLJBmDnRJJttLUyqiKArPw3dqse7DKcNG6SUUL2QU";
	std::string viewkey_str = "42f1078af565a473bf34328fa9c0d1a0baf958acbe435fc6552486fa54699a0c";
	std::string spendkey_str = "";

	bool SPEND_KEY_GIVEN = false;

	if (!get_account_address_from_str(address_info, nettype, address_str))
	{
		std::cerr << "Cant parse string address: " << address_str << '\n';
		return 1;
	}

	cryptonote::account_public_address address = address_info.address;

	// parse string representing given private viewkey
	crypto::secret_key prv_view_key;

	if (!xmreg::parse_str_secret_key(viewkey_str, prv_view_key))
	{
		std::cerr << "Cant parse view key: " << viewkey_str << '\n';
		return 1;
	}

	crypto::secret_key prv_spend_key;

	// parse string representing given private spend
	if (SPEND_KEY_GIVEN && !xmreg::parse_str_secret_key(spendkey_str, prv_spend_key))
	{
		std::cerr << "Cant parse spend key: " << spendkey_str << '\n';
		return 1;
	}

	cryptonote::account_keys admin_keys;

	if (SPEND_KEY_GIVEN)
	{
		// set account keys values
		admin_keys.m_account_address = address;
		admin_keys.m_spend_secret_key = prv_spend_key;
		admin_keys.m_view_secret_key = prv_view_key;
	}

	// lets check our keys
	std::cout << '\n'
			  << "address          : " << xmreg::print_address(address_info, nettype) << '\n'
			  << "private view key : " << prv_view_key << '\n';

	if (SPEND_KEY_GIVEN)
		std::cout << "private spend key: " << prv_spend_key << '\n';
	else
		std::cout << "private spend key: "
				  << "not given\n";

	std::cout << '\n';

	// simple as veryfing if a given key_image exist in our vector.
	std::vector<crypto::key_image> key_images_admin;
	std::vector<xmreg::transfer_details> found_outputs;

	for (uint64_t i = 160; i < height; ++i)
	{
		cryptonote::block blk;

		try
		{
			blk = core_storage->get_db().get_block_from_height(i);
		}
		catch (std::exception &e)
		{
			std::cerr << e.what() << '\n';
			continue;
		}
		std::cout << "Analysing block\t"<< i << '\t' << mktime << std::endl;

		// get all transactions in the block found
		// initialize the first list with transaction for solving
		// the block i.e. coinbase.
		std::vector<cryptonote::transaction> txs{blk.miner_tx};
		std::vector<crypto::hash> missed_txs;

		if (!mcore.get_core().get_transactions(blk.tx_hashes, txs, missed_txs))
		{
			std::cerr << "Cant find transactions in block: " << i << '\n';
			continue;
		}

		std::cout << "transaction in block\t" << i << '\n';
		for (const cryptonote::transaction &tx : txs)
		{
			crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

				try
				{
					// output only our outputs
					found_outputs = xmreg::get_belonging_outputs(
						blk, tx, address, prv_view_key, i);
				}
				catch (std::exception const &e)
				{
					std::cerr << e.what() << " for tx: " << epee::string_tools::pod_to_hex(tx_hash)
							  << " Skipping this tx!" << std::endl;
					continue;
				}
		}
	}
	std::cout << "print vector output" << '\n';
		for (auto i = found_outputs.begin(); i != found_outputs.end(); ++i)
    		std::cout << *i << ' ';

	return 0;
}