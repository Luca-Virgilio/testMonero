
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
	std::string address_str = "58EnGZ7JPUyTANYYmZWizYfZoAjnVuWvP3FsMCF74UJHVsMnT3dkHfuFCucwK5xJ7MKAizex3RhA3DnYTXRw7rFw6vFniAU";
	std::string viewkey_str = "8a12073d5292a8e99a7eec4f70c5d24c2cef3290121e61b9fd916ed0461dd300";
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
	// old //
	//std::vector<crypto::key_image> key_images_admin;
	std::vector<crypto::public_key> admin_outputs;

	for (uint64_t i = 0; i < height; ++i)
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
		std::cout << "Analysing block\t" << i << '\t' << mktime << std::endl;

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
				std::vector<xmreg::transfer_details> admin_outputs_founded = xmreg::get_belonging_outputs(
					blk, tx, address, prv_view_key, i);
				if (admin_outputs_founded.size() != 0)
				{
					std::cout << admin_outputs_founded.size() << " admin outputs fount at " << i << '\n';
					for (auto i = admin_outputs_founded.begin(); i != admin_outputs_founded.end(); ++i)
					{
						// std::cout << *i << '\n';
						// std::cout << i->out_pub_key << '\n';
						admin_outputs.push_back(i->out_pub_key);
					}
				}
			}
			catch (std::exception const &e)
			{
				std::cerr << e.what() << " for tx: " << epee::string_tools::pod_to_hex(tx_hash)
						  << " Skipping this tx!" << std::endl;
				continue;
			}
			// thus check for inputs,
			// we want to check only if our outputs were used
			// as ring members somewhere 483
			size_t input_no = tx.vin.size();
			// to delte //std::cout << "txin_to_key" << typeid(cryptonote::txin_to_key)) <<"\n";
			if (input_no > 0)
			{
				std::cout << "input mixin " << input_no << "\n";
				if (tx.vin[0].type() == typeid(cryptonote::txin_to_key))
					std::cout << "found " << input_no << " inputs in block " << i << '\n';
			}

			for (size_t ii = 0; ii < input_no; ++ii)
			{

				if (tx.vin[ii].type() != typeid(cryptonote::txin_to_key))
					continue;

				// get tx input key
				const cryptonote::txin_to_key &tx_in_to_key = boost::get<cryptonote::txin_to_key>(tx.vin[ii]);
				uint64_t xmr_amount = tx_in_to_key.amount;

				if (!(rct::scalarmultKey(rct::ki2rct(tx_in_to_key.k_image),
										 rct::curveOrder()) == rct::identity()))
				{
					std::cerr << "Found key image with wrong domain: "
							  << epee::string_tools::pod_to_hex(tx_in_to_key.k_image)
							  << " in tx: " << epee::string_tools::pod_to_hex(tx_hash)
							  << std::endl;
					return 1;
				}

				// get absolute offsets of mixins
				std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);
				std::vector<cryptonote::output_data_t> mixin_outputs;

				std::cout << "absolute offsets:" << '\n';
				for (auto ab = absolute_offsets.begin(); ab != absolute_offsets.end(); ++ab)
				{
					std::cout << *ab << '\n';
				}

				try
				{
					core_storage->get_db().get_output_key(
						epee::span<uint64_t const>(&xmr_amount, 1),
						absolute_offsets, mixin_outputs);
				}
				catch (const cryptonote::OUTPUT_DNE &e)
				{
					std::cerr << "Mixins key images not found" << '\n';
					continue;
				}
				// mixin counter
				size_t count = 0;

				// for each found output public key check if its ours or not
				for (const uint64_t &abs_offset : absolute_offsets)
				{
					// get basic information about mixn's output
					cryptonote::output_data_t output_data = mixin_outputs.at(count);

					// check our known outputs cash
					// if the key exists

					std::cout << "pubkey: " << output_data.pubkey << "\n";
					auto it = std::find_if(
						admin_outputs.begin(),
						admin_outputs.end(),
						[&](const crypto::public_key &known_key) {
							return output_data.pubkey == known_key;
						});

					if (it == admin_outputs.end())
					{
						// this mixins's output is unknown.
						std::cout << "mixins's output is unkonwn"
								  << "\n";
						++count;
						continue;
					}

					// this seems to be our mixin.
					std::cout << "- found output as ring member: " << (count + 1)
							  << "\n"
							  << "key: " << *it
							  << "\t"
							  << "tx_hash: "
							  << tx_hash << '\n';
					++count;
				}
			}
		}
	}
	// std::cout << "print vector output:" << '\n';
	// for (auto i = admin_outputs.begin(); i != admin_outputs.end(); ++i)
	// {
	// 	std::cout << *i << '\n';
	// }

	return 0;
}