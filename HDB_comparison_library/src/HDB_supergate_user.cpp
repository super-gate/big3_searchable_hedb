#include <iostream>
#include <string_view>

#include <helib/debugging.h>
#include <NTL/mat_ZZ.h>
#include <NTL/ZZX.h>
#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "HDB_supergate_user.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include "binio.h"
#include <time.h>
#include <filesystem>
#include <fstream>
#include <sstream>

using namespace NTL;
using namespace std;
using namespace he_cmp;
using namespace HDB_supergate_;
using namespace helib;

namespace fs = std::filesystem;

namespace HDB_supergate_user_{

	USER::USER(bool verbose) : verbose(verbose) {}

    /* Deprecated Construction for simulation DB only*/
    // USER::USER(Comparator& comparator, Context& contx, PubKey& pk, SecKey& sk, bool v) : comparator(comparator), contx(contx), pk(pk), sk(sk), verbose(v) {};

	void USER::constructPathName(BGV_param param, string& name)
	{
		stringstream full_path;
		full_path << "./KEY_STORAGE/" 
                  << param.p << "_" << param.m << "_" << param.nb_primes << "_" << param.c << "_" << param.r << "_" << param.scale << "_" << param.d << "_" << param.expansion_len;
		name = full_path.str();
	}

	void USER::saveInfo(BGV_param param)
	{
		if (verbose) cout << "Saving Information to Storage..." << endl;
		string filepath;
		constructPathName(param, filepath);
        fs::create_directories(filepath);

        string context_filename = filepath + "/context";
        serialize_to_file(context_filename, *Contx);

        string pk_filename = filepath + "/pubkey";
        serialize_to_file(pk_filename, *PublicKey);

        string sk_filename = filepath + "/seckey";
        serialize_to_file(sk_filename, *SecretKey);
	}

	void USER::HandleSecKey(BGV_param param)
	{
		if (verbose) cout << "Creating Secret Key..." << endl;
		SecKey secret_key(*Contx); 
		secret_key.GenSecKey();
		
		//automorphism
		if (param.expansion_len > 1)
		{
			if (Contx->getZMStar().numOfGens() == 1)
			{
				std::set<long> automVals;
				long e = 1;
				long ord = Contx->getZMStar().OrderOf(0);
				bool native = Contx->getZMStar().SameOrd(0);
				if(!native)
					automVals.insert(Contx->getZMStar().genToPow(0, -ord));
				while (e < param.expansion_len){
					long atm = Contx->getZMStar().genToPow(0, ord-e);
					automVals.insert(atm);
					e <<=1;
				}
				addTheseMatrices(secret_key, automVals);
			}
			else
			{
			addSome1DMatrices(secret_key);
			}
		}

		if (param.d>1)
			addFrbMatrices(secret_key);
		SecretKey = make_unique<SecKey>(secret_key);
	}

	void USER::HandlePubKey()
	{
		if (verbose) cout << "Creating Public Key..." << endl;
		PubKey pk(*SecretKey);
		PublicKey = make_unique<PubKey>(pk);
	}

	void USER::DestroyKeys()
	{
		Contx.reset(nullptr);
		PublicKey.reset(nullptr);
		SecretKey.reset(nullptr);
	}

	pair<PubKey, SecKey> USER::generateKeys(Context* contx, BGV_param param)
	{
		Contx.reset(contx);
		HandleSecKey(param);
		HandlePubKey();
		saveInfo(param);
		contx = Contx.release();
		PubKey pk = *PublicKey;
		SecKey sk = *SecretKey;
		pair<PubKey, SecKey> key_pair(pk, sk);
		DestroyKeys();
		return key_pair;
	}

	unsigned long USER::max(){
		return input_range;
	};

	int8_t USER::loadDecryptionInfo(BGV_param param)
	{
		string key_path;
        constructPathName(param, key_path);
		if (!fs::exists(key_path))
        {
            cerr << "Path: " << key_path << " does not exist." << endl;
            return -1;
        }

		if (loadContext(key_path) == -1) return -1;
        if (loadSecKey(key_path) == -1) return -1;
		loadRest(key_path, param);
		return 0;
	}

	void USER::printQueryResult(BGV_param param, Ctxt_mat& result, Q_MODE mode)
	{
		if (verbose) cout << "Loading Decryption information..." << endl;
		if (loadDecryptionInfo(param) == -1) 
		{
			cerr << "cannot load decrpytion information" << endl;
			return;
		}
		if (verbose) cout << "Here are the query results:" << endl;
		if (mode == EXTF) printCtxtMatINT(result, true);
		else printCtxtMatINT(result);
		ClearInfo();
	}

	void USER::printZZXasINT(vector<ZZX> decrypted)
	{
		ZZ data = ZZ(0);
		for (unsigned long i = 0; i < nslots; ++i)
		{
			unsigned long mod = i % exp_len;
			vec_ZZ polyRep = decrypted[i].rep;
			for (long j = 0; j < polyRep.length(); ++j)
			{
				unsigned long exp = mod * D + j;
				ZZ elem = polyRep[j];
				elem *= pow(enc_base, exp);
				data += elem;
			}
			if (mod == exp_len - 1)
			{
				if (data == ZZ(0)) continue;
				cout << data << ", ";
				data = ZZ(0);
			}
		}
	}

	/**
	 * For every explen, 
	 * 1. gather all data packed
	 * 2. both come up with equation and the calculated value
	 */
	void USER::printPackedZZXasINT(vector<ZZX> decrypted)
	{
		vector<ZZ> data(ord_p/D, ZZ(0));
		vector<stringstream> datastring(ord_p/D);
		for (unsigned long i = 0; i < nslots; ++i)
		{
			unsigned long mod = i % exp_len;
			vec_ZZ polyRep = decrypted[i].rep;
			for (long j = 0; j < polyRep.length(); ++j)
			{
				unsigned long exp = (j % D) + (mod * (D-1)); // if D == 3 [0, 1, 2, 0, 1, 2, ...], [3, 4, 5, 3, 4, 5, ...]
				ZZ elem = polyRep[j];
				if (elem == ZZ(0)) continue;
				datastring[j/D] << elem << "*"
				elem *= pow(enc_base, exp);
				data[j/D] += elem;
				datastring[j/D] << enc_base << "^" << exp << " + ";
			}
			if (mod == exp_len - 1)
			{
				for (int c = 0; c < data.size(); ++c) 
				{
					if (data[c] == ZZ(0)) continue;
					cout << "[" << datastring[c] << "= " << data[c] << "], ";
				}
				for (auto& d: data) d = ZZ(0);
				for (auto& s: datastring) s.clear();
			}
		}
	}

	void USER::printDecryptedZZX(Ctxt& ctxt)
    {
        vector<ZZX> decrypted_cipher(nslots);
        ea->decrypt(ctxt, *SecretKey, decrypted_cipher);
		
		cout << "Enc( ";
		for (auto & zzx: decrypted_cipher)
        	printZZX(cout, zzx);
		cout << " ), ";
    };


	void USER::printDecryptedINT(Ctxt& ctxt, bool zzx_packed)
    {
        vector<ZZX> decrypted_cipher(nslots);
        ea->decrypt(ctxt, *SecretKey, decrypted_cipher);

		// cout << "Enc( ";
        if (zzx_packed) printPackedZZXasINT(decrypted_cipher);
		else printZZXasINT(decrypted_cipher);
		// cout << " ), ";
    };

	void USER::printCtxtVecINT(Ctxt_vec& v, bool zzx_packed)
	{
		for (auto& elem: v)
			printDecryptedINT(elem, zzx_packed);
	}

	void USER::printCtxtVecZZX(Ctxt_vec& v)
	{
		for (auto& elem: v)
			printDecryptedZZX(elem);
	}

	void USER::printCtxtMatZZX(Ctxt_mat& db)
	{
		for (auto& row: db)
		{
			cout << "Row\n";
			printCtxtVecZZX(row);
			cout << endl;
		}
	}

	void USER::printCtxtMatINT(Ctxt_mat& db, bool zzx_packed)
	{
		for (auto& row: db)
		{
			cout << "Row\n";
			printCtxtVecINT(row, zzx_packed);
			cout << endl;
		}
	}

	void USER::EncryptNumberPerSlot(Ctxt& ctxt, long input)
	{
		vector<ZZX> poly_input(nslots);
		input %= input_range;
		for (unsigned long i = 0; i < nslots; ++i)
			poly_input[i] = ZZX(input);
        ea->encrypt(ctxt, *PublicKey, poly_input);
	}

	void USER::EncryptNumber(Ctxt& ctxt, unsigned long input) 
	{
		vector<ZZX> poly_input(nslots);
		input %= input_range;
		for (unsigned long i = 0; i < max_packed; ++i)
			dataToZZXSlot(input,
						  poly_input,
						  i,
						  digit_base,
						  exp_len,
						  enc_base,
						  *Comp);
        ea->encrypt(ctxt, *PublicKey, poly_input);
	}
		
	HEQuery* USER::ConstructQuery(BGV_param param,
							  unsigned long input,
					 		  Q_TYPE_t type,
					 		  long source,
							  vector<long> dest)
	{
		loadEncryptionInfo(param);
		if (verbose) cout << "Constructing Query...\n";
		HEQuery* q = new HEQuery(*PublicKey);

		Ctxt query_ctxt(*PublicKey);
		Ctxt eq(*PublicKey);
		Ctxt lt(*PublicKey);

		EncryptNumber(query_ctxt, input);
		if (type != LT) EncryptNumberPerSlot(eq, 1);
		else EncryptNumberPerSlot(eq, 0);
		if (type != EQ) EncryptNumberPerSlot(lt, 1);
		else EncryptNumberPerSlot(lt, 0);
		
		q->insert(source, eq, lt, query_ctxt, dest);
		if (verbose) cout << "Query Constructed" << endl;
		ClearInfo();
		return q;
    };

	int8_t USER::loadContext(string key_path)
	{
		if (verbose) cout << "Loading Context...\n";
        ifstream inContextFile;
        string context_filename = key_path + "/context";
        inContextFile.open(context_filename);
        if (!inContextFile.is_open()) {
            cerr << "Could not open file 'context'." << endl;
            return -1;
        }
        Context* contx = Context::readPtrFrom(inContextFile);
        inContextFile.close();
        Contx.reset(contx);
        return 0;
	}

	int8_t USER::loadPubKey(string key_path)
    {
        if (verbose) cout << "Loading Public Key...\n";
        ifstream inPubKeyFile;
        string pubkey_filename = key_path + "/pubkey";
        inPubKeyFile.open(pubkey_filename);
        if (!inPubKeyFile.is_open()) {
            cerr << "Could not open file 'pubkey'." << endl;
            return -1;
        }
        PubKey pk = PubKey::readFrom(inPubKeyFile, *Contx);
        inPubKeyFile.close();
        PublicKey = make_unique<PubKey>(pk);
        return 0;
    }

	int8_t USER::loadComparator(BGV_param param)
    {
        if (verbose) cout << "Loading Comparator ...\n";
        Comparator* newComp = new Comparator(*Contx, UNI, param.d, param.expansion_len, *PublicKey, verbose);
        Comp.reset(newComp);
        return 0;
    }

	int8_t USER::loadSecKey(string key_path)
	{
		if (verbose) cout << "Loading Secret Key...\n";
        ifstream inSecKeyFile;
        string seckey_filename = key_path + "/seckey";
        inSecKeyFile.open(seckey_filename);
        if (!inSecKeyFile.is_open()) {
            cerr << "Could not open file 'seckey'." << endl;
            return -1;
        }
        SecKey sk = SecKey::readFrom(inSecKeyFile, *Contx);
        inSecKeyFile.close();
        SecretKey = make_unique<SecKey>(sk);
        return 0;
	}

	void USER::loadRest(string key_path, BGV_param param)
	{
		if (verbose) cout << "Loading other Encryption Information..." << endl;
		ea = make_unique<const EncryptedArray>(Contx->getView());
		p = param.p;
		ord_p = Contx->getOrdP();
		D = param.d;
		nslots = Contx->getNSlots();
		exp_len = param.expansion_len;
		max_packed = nslots / exp_len;
		enc_base = (p + 1) >> 1;
		digit_base = power_long(enc_base, D);
		space_bit_size = static_cast<int>(ceil(exp_len * log2(digit_base)));
        input_range = space_bit_size < 64 ? power_long(digit_base, exp_len) : ULONG_MAX;
	}

	int8_t USER::loadEncryptionInfo(BGV_param param)
	{
		string key_path;
        constructPathName(param, key_path);
		if (!fs::exists(key_path))
        {
            cerr << "Path: " << key_path << " does not exist." << endl;
            return -1;
        }

		if (loadContext(key_path) == -1) return -1;
        if (loadPubKey(key_path) == -1) return -1;
        if (loadComparator(param) == -1) return -1;
		loadRest(key_path, param);
		return 0;
	}

	void USER::ClearInfo()
	{
		DestroyKeys();
		Comp.reset(nullptr);
		ea.reset(nullptr);
		ptxt_index_file.clear();
		p = 0;
		ord_p = 0;
		D = 0;
		nslots = 0;
		exp_len = 0;
		max_packed = 0;
		enc_base = 0;
		digit_base = 0;
		space_bit_size = 0;
		input_range = 0;
	}

	void USER::EncryptData(string db_path,
                    	   BGV_param param,
						   Ctxt_mat& db,
						   vector<string>& headers,
						   CtxtIndexFile& indFile,
                           bool index)
	{
		loadEncryptionInfo(param);
		if (verbose) cout << "Encryption Info loaded....\nConverting CSV to Ciphertext..." << endl;
		csvToDB(db, db_path, headers);
		if (index)
		{
			createPtxtIndexFile(db_path);
			createCtxtIndexFile(indFile);
		}
		ClearInfo();
		cout << "Done\n" << endl;
	}

	void USER::createPtxtIndexFile(string path)
	{
		vector<string> headers; // headers are column names
		CSVRange reader(*(new ifstream(path)));
		for (auto& row: reader)
        {
            for (unsigned int i = 1; i < row.size(); ++i)
                headers.emplace_back(row[i]);
            break;
        }
		int counter = 1;
		for (auto& row: reader)
		{
			for (unsigned int i = 1; i < row.size(); ++i) 
			{
				/* Index looks like [<key, [uid]>]
				 * Index File looks like [ <colname, Index> ]
				 */
				ptxt_index_file.insert(headers[i-1], stol(string{row[i]}), counter);
			}
			counter++;
		}
		cout << "created ptxtIndexFile" << endl;
	}

	void USER::createCtxtIndexFile(CtxtIndexFile& file)
	{
		file.encrypt(ptxt_index_file,
					 *Comp,
					 *Contx,
					 *PublicKey,
					 input_range,
					 digit_base,
					 enc_base,
					 exp_len,
					 nslots,
					 max_packed,
					 verbose
					);
	}
	
    void USER::csvToDB(Ctxt_mat& db, string path, vector<string>& headers)
    {
        CSVRange reader(*(new ifstream(path)));
        for (auto& row: reader)
        {
            for (unsigned int i = 0; i < row.size(); ++i)
                headers.emplace_back(row[i]);
            break;
        }
        csvToDB(db, reader);
    }

	void USER::getCSVHeaders(string path, vector<string>& headers)
	{
		CSVRange reader(*(new ifstream(path)));
        for (auto& row: reader)
        {
            for (unsigned int i = 0; i < row.size(); ++i)
                headers.emplace_back(row[i]);
            break;
        }
	}

    void USER::csvToDB(Ctxt_mat& db, string path)
    {
        CSVRange reader(*(new ifstream(path)));
        csvToDB(db, reader);
    }

    void USER::csvToDB(Ctxt_mat& db, CSVRange& reader) {
		vector<vector<ZZX>> ptxt_data;

		unsigned long counter = 0;

        for (auto& row: reader)
        {
			// cout << "for each row..." << endl;
			for (unsigned int i = 0; i < row.size(); ++i) 
			{
				if (!counter)
				{
					ptxt_data.emplace_back(*(new vector<ZZX>{nslots}));
				}
				dataToZZXSlot(stol(string{row[i]}) % input_range,
							  ptxt_data[i],
							  counter,
							  digit_base,
							  exp_len,
							  enc_base,
							  *Comp);
			}
			counter++;
			if (counter == max_packed)
			{
				for (unsigned int i = 0; i < row.size(); ++i) 
				{
					if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
					encryptAndInsert(*Contx, *PublicKey, ptxt_data[i], db[i]);

				}
				counter = 0;
				ptxt_data.clear();
			}
        }
		if (counter > 0) 
		{
			for (unsigned int i = 0; i < ptxt_data.size(); ++i) 
			{
				if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
				encryptAndInsert(*Contx, *PublicKey, ptxt_data[i], db[i]);
			}
		}
		// if (verbose)
		cout << "created db with " << db.size() << " rows each with " << db[0].size() << " ciphertexts." << endl;
    }
}

