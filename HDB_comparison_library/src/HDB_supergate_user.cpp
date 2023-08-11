#include<iostream>
#include <string_view>

#include <helib/debugging.h>
#include <NTL/mat_ZZ.h>
#include <NTL/ZZX.h>
#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "HDB_supergate_user.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include <time.h>

using namespace NTL;
using namespace std;
using namespace he_cmp;
using namespace HDB_supergate_;
using namespace helib;

namespace HDB_supergate_user_{
    /* Construction */
    USER::USER(Comparator& comparator, const Context& contx, PubKey& pk, SecKey& sk, bool v) : comparator(comparator), contx(contx), pk(pk), sk(sk), verbose(v) {};

	unsigned long USER::max(){
		return input_range;
	};

	void USER::printZZXasINT(vector<ZZX> decrypted)
	{
		ZZ data = ZZ(0);
		for (unsigned long i = 0; i < nslots; ++i)
		{
			unsigned long mod = i % exp_len;
			vec_ZZ polyRep = decrypted[i].rep;
			for (unsigned long j = 0; j < polyRep.length(); ++j)
			{
				unsigned long exp = mod * D + j;
				ZZ elem = polyRep[j];
				elem *= pow(enc_base, exp);
				data += elem;
			}
			if (mod == exp_len - 1)
			{
				cout << "[" << data << "], ";
				data = ZZ(0);
			}
		}
	}

	void USER::printPackedZZXasINT(vector<ZZX> decrypted)
	{
		vector<ZZ> data(ord_p/D, ZZ(0));
		for (unsigned long i = 0; i < nslots; ++i)
		{
			for (auto& d: data) d = ZZ(0);
			vec_ZZ polyRep = decrypted[i].rep;
			for (unsigned long j = 0; j < polyRep.length(); ++j)
			{
				unsigned long exp = j % D;
				ZZ elem = polyRep[j];
				elem *= pow(enc_base, exp);
				data[j/D] += elem;
			}
			cout << "[";
			for (auto & d: data) 
			{
				if (d == ZZ(0)) continue;
				cout << d << ", ";
			}
			cout << "]";
		}
	}

	void USER::printDecryptedZZX(Ctxt& ctxt)
    {
        vector<ZZX> decrypted_cipher(nslots);
        contx.getView().decrypt(ctxt, sk, decrypted_cipher);
		
		cout << "Enc( ";
		for (auto & zzx: decrypted_cipher)
        	printZZX(cout, zzx);
		cout << " ), ";
    };


	void USER::printDecryptedINT(Ctxt& ctxt, bool zzx_packed)
    {
        vector<ZZX> decrypted_cipher(nslots);
        contx.getView().decrypt(ctxt, sk, decrypted_cipher);

		cout << "Enc( ";
        if (zzx_packed) printPackedZZXasINT(decrypted_cipher);
		else printZZXasINT(decrypted_cipher);
		cout << " ), ";
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
        contx.getView().encrypt(ctxt, pk, poly_input);
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
						  comparator);
        contx.getView().encrypt(ctxt, pk, poly_input);
	}
		
	void USER::ConstructQuery(HEQuery& q,
							  unsigned long input,
					 		  Q_TYPE_t type,
					 		  long source,
							  vector<long> dest)  
	{
		Ctxt query_ctxt(pk);
		Ctxt eq(pk);
		Ctxt lt(pk);

		EncryptNumber(query_ctxt, input);
		if (type != LT) EncryptNumberPerSlot(eq, 1);
		else EncryptNumberPerSlot(eq, 0);
		if (type != EQ) EncryptNumberPerSlot(lt, 1);
		else EncryptNumberPerSlot(lt, 0);
		
		q.insert(source, eq, lt, query_ctxt, dest);
    };

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

	void USER::createCtxtIndexFile(HDB_supergate_::CtxtIndexFile& file)
	{
		file.encrypt(ptxt_index_file,
					 comparator,
					 contx,
					 pk,
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
							  comparator);
			}
			counter++;
			if (counter == max_packed)
			{
				for (unsigned int i = 0; i < row.size(); ++i) 
				{
					if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
					encryptAndInsert(contx, pk, ptxt_data[i], db[i]);

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
				encryptAndInsert(contx, pk, ptxt_data[i], db[i]);
			}
		}
		// if (verbose)
		cout << "created db with " << db.size() << " rows each with " << db[0].size() << " ciphertexts." << endl;
    }
}

