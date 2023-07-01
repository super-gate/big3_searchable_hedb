#include <stdio.h>
#include <iostream>

#include <helib/helib.h>
#include <helib/ArgMap.h>

#include "../HDB_comparison_library/comp_lib/comparator.h"
#include "HDB_supergate.hpp"
#include "HDB_supergate_server.hpp"
#include "HDB_supergate_user.hpp"
#include <NTL/ZZX.h>
#include <time.h>

// NAMESAPCE name should be defferent from its file name...
using namespace HDB_supergate_;
using namespace HDB_supergate_user_;
using namespace HDB_supergate_server_;


/*HELIB*/
using namespace helib;
using namespace std;
using namespace he_cmp;
using namespace NTL;

int main(int argc, char* argv[]) {
	unsigned long p = 2;      	    // p=2 gives best efficiency
	unsigned long m = 131071; 	    // should give 7710 slots
	unsigned long r = 1;      	    // TODO: if time, research into this
	unsigned long bits = 500; 	    // TODO: need to specify bits for security/arithmetic_depth tradeoff
	unsigned long c = 3;      	    // 2 or 3 should be good
	unsigned long d = 3;	  	    // expansion depth. For UNI, max (p+1)/2 -> ((p+1)/2)^d-1
	unsigned long l = 3;	  	    // expansion length. For UNI, max ((p+1)/2)^d -> (((p+1)/2)^d)^l-1
	unsigned long scale = 6;  	    // TODO: scale factor, research if time
	string db_filename = "insurance_int_encoded";  // db filename

	bool verbose = false;			    // if true lots of debug info
	bool std128 = false;				// if true, just use HDB_STD128 params, else use the default+user params

	helib::ArgMap amap;
	amap.arg("m", m, "Cyclotomic polynomial ring (default 131071)");
	amap.arg("p", p, "Plaintext prime modulus (default 2)");
	amap.arg("r", r, "Hensel lifting (default 1)");
	amap.arg("bits", bits, "# of bits in the modulus chain (default 500)");
	amap.arg("c", c, "# fo columns of Key-Switching matrix (default 3)");
	amap.arg("d", d, "Extend plaintext modulus by ((p+1)/2)^d (default 3)");
	amap.arg("l", l, "Expansion length, (((p+1)/2)^d)^l (default 3)");
	amap.arg("scale", scale, "Expansion length, (((p+1)/2)^d)^l (default 6)");
	amap.arg("db_filename",
			db_filename,
			"Qualified name for the csv database filename(default: stroke_int_encoded)");
	amap.toggle().arg("-v", verbose, "Toggle verbose", "");

	amap.toggle().arg("-std", std128, "Toggle to just use standard128 params", "");
	amap.parse(argc, argv);

	const struct BGV_param HDB_Param = std128 ? TOY_HDB : MakeBGVParam(p, d, m, bits, c, l, scale, r);

	HELIB_NTIMER_START(timer_Context);
    const Context contx = MakeBGVContext(HDB_Param); //TODO: Test Parameters
	HELIB_NTIMER_STOP(timer_Context);
    cout << "Q size: " << contx.logOfProduct(contx.getCtxtPrimes())/log(2.0) << endl;
    cout << "Q*P size: " << contx.logOfProduct(contx.fullPrimes())/log(2.0) << endl;
    cout << "Security: " << contx.securityLevel() << endl;    
    cout<<"///////////////////////////////////"<<endl;
	contx.getZMStar().printout();
	cout<<endl;
	cout<<"/////////////////////////////////////"<<endl;

	HELIB_NTIMER_START(timer_SecKey);
    SecKey secret_key(contx); 
    secret_key.GenSecKey();
	
	//automorphism
    if (HDB_Param.expansion_len > 1)
	{
		if (contx.getZMStar().numOfGens() == 1)
		{
			std::set<long> automVals;
			long e = 1;
			long ord = contx.getZMStar().OrderOf(0);
			bool native = contx.getZMStar().SameOrd(0);
			if(!native)
				automVals.insert(contx.getZMStar().genToPow(0, -ord));
			while (e < HDB_Param.expansion_len){
				long atm = contx.getZMStar().genToPow(0, ord-e);
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

	if (HDB_Param.d>1)
		addFrbMatrices(secret_key);
	HELIB_NTIMER_STOP(timer_SecKey);

	// make public key
	HELIB_NTIMER_START(timer_PubKey);
	PubKey public_key(secret_key);
	HELIB_NTIMER_STOP(timer_PubKey);
	
	CircuitType type = UNI; //Fixed at UNI
	Comparator comparator(contx, type, HDB_Param.d, HDB_Param.expansion_len, public_key, false); // secret key deleted. only public key remained

	/*Secret key is contained in this class. Be carefull! */
    USER user = USER(comparator, contx, public_key, secret_key, verbose); //pass secret key only to user

	Ctxt_mat db;
	vector<string> headers;
	db_filename = "../db/" + db_filename + ".csv";
	user.createPtxtIndexFile(db_filename);
	if (verbose)
		user.getPtxtIndexFile().printIndexFile();
	HELIB_NTIMER_START(timer_Encrypt_DB);
	user.csvToDB(db, db_filename, headers);
	HELIB_NTIMER_STOP(timer_Encrypt_DB);
    cout << endl;

	if (verbose)
	{
		for (auto& h:headers)
			cout << "\nhead: " << h;
		cout << endl;
		user.printCtxtMat(db);
	}
	

	HELIB_NTIMER_START(timer_IndexFile);
	CtxtIndexFile indFile;
	user.createCtxtIndexFile(indFile);
	HELIB_NTIMER_STOP(timer_IndexFile);
	// Ctxt test = db[0][0];
	// for (int neg = -1; neg >= -50; neg--)
	// {
	// 	HELIB_NTIMER_START(timer_rotate_neg);
	// 	shift(test, neg);
	// 	// user.printDecrypted(test);
	// 	HELIB_NTIMER_STOP(timer_rotate_neg);
	// 	cout << "neg: " << neg;
	// 	helib::printNamedTimer(std::cout, "timer_rotate_neg");
	// }
	// HELIB_NTIMER_START(timer_rotate_neg);
	// shift(test, -3117);
	// user.printDecrypted(test);
	// HELIB_NTIMER_STOP(timer_rotate_neg);
	// helib::printNamedTimer(std::cout, "timer_rotate_neg");
	// HELIB_NTIMER_START(timer_rotate);
	// shift(test, 1);
	// user.printDecrypted(test);
	// HELIB_NTIMER_STOP(timer_rotate);
	// HELIB_NTIMER_START(timer_shift);
	// shift(test, 1);
	// user.printDecrypted(test);
	// HELIB_NTIMER_STOP(timer_shift);
	// HELIB_NTIMER_START(timer_total_sum);
	// totalSums(test);
	// user.printDecrypted(test);
	// HELIB_NTIMER_STOP(timer_total_sum);
	// helib::printNamedTimer(std::cout, "timer_rotate");
	// helib::printNamedTimer(std::cout, "timer_shift");
    // helib::printNamedTimer(std::cout, "timer_total_sum");
	// return 1;
	cout << "created index file" << endl;
	/*SERVER SIDE */   
    SERVER server = SERVER(comparator, db, indFile, verbose);
	cout << "created server" << endl;
	/*
	 * 1. readCSV() => reads csv file and populates plaintext DB
	 * 2. DB is encrypted and stored in server
	 * 3. makeIndex() => creates index file according to algorithm
	 * 4. Index file is encrypted and stored in server
	 * 5. SERVER::query() => params: query_col_index, query_ctxt, query_type, dest_query_indexes, returns: dest_query_result
	 * 6. USER::decryptResult() => user decrypts result
	 * 7. Make user in a loop so that we can query multiple times into one server (so that we don't have to instantiate everything for each query)
	 */
    Q_TYPE_t queryType;
	string str;
	while(true)
	{
		cout<<"the type has to be one of (eq, lt, leq)."<<endl;
		cout<<"input type: ";
		cin>>str;
		if(str == "eq")
		{
			queryType = EQ;
			break;
		}
		else if(str == "lt")
		{
			queryType = LT;
			break;
		}
		else if(str == "leq")
		{
			queryType = LEQ;
			break;
		}
	}

	unsigned long max = user.max();

	unsigned long input;
	while(true)
	{
		cout<<"maximum int is "<<max - 1<<endl;
		cout<<"input query: ";
		cin>>input;

		if(input < max)
		{
			break;
		}
	}

	vector<unsigned long> dest = {2}; //TODO: try more dest columns
	unsigned long source = 0;
	HEQuery q(public_key);
	user.ConstructQuery(q, input, queryType, source, dest);

	Ctxt_mat result;
	HELIB_NTIMER_START(timer_Query);
    // server.QueryWithIndex(q, result);
	// server.Query(q, result);
	CtxtIndex& Index = indFile.find(q.source);
	unsigned long X = Index.getX();
	unsigned long Y = Index.getY();

	result.resize(q.dest.size()); // resize result so we have #dest rows
	for (auto& row: result) row.reserve(Y);

	unsigned long nslots = comparator.m_context.getNSlots();
	unsigned long exp_len = comparator.m_expansionLen;
	unsigned long D = comparator.m_slotDeg;
	unsigned long max_packed = nslots / exp_len;

	Ctxt_vec q_mod_p;
	comparator.extract_mod_p(q_mod_p, q.query);

	Ctxt_vec intermediates;
	intermediates.reserve(Y);
	for (auto& k_ctxt: Index.keys()) {
		Ctxt_vec ctxt_eq_p;
		Ctxt_vec k_mod_p;
		comparator.extract_mod_p(k_mod_p, k_ctxt);
		for (long iCoef = 0; iCoef < D; iCoef++)
		{
			Ctxt eql = q_mod_p[iCoef];
			eql -= k_mod_p[iCoef];
			//equality circuit
			comparator.mapTo01_subfield(eql, 1);
			eql.negate();
			eql.addConstant(ZZ(1));
			ctxt_eq_p.push_back(eql);
		}
		Ctxt ctxt_eq = ctxt_eq_p[D-1];
		for(long iCoef = D - 2; iCoef >= 0; iCoef--)
			ctxt_eq *= ctxt_eq_p[iCoef];
		intermediates.emplace_back(ctxt_eq);
	}
	cout << "A done" << endl;

	Ctxt_mat UID_extract = Index.uids(); //copy of the uids table
	for (auto& row: UID_extract)
	{
		for (unsigned long c = 0; c < Index.getY(); ++c)
			row[c] *= intermediates[c];
	}
	cout << "B done" << endl;
	user.printCtxtMat(UID_extract);

	intermediates.clear();
	intermediates = UID_extract[0];
	cout << "X: " << X << " Y: " << Y << endl;
	for (int i = 1; i < X; ++i) //rotate and add
	{
		cout << " i: " << i << endl;
		Ctxt_vec rot = UID_extract[i];
		cout << "rot.size: " << rot.size() << endl;
		for (auto& r: rot) 
		{
			HELIB_NTIMER_START(timer_rotate);
			rotate(r, -1 * exp_len * i);
			HELIB_NTIMER_STOP(timer_rotate);
		}
		printNamedTimer(cout, "timer_rotate");
		cout << "   rotate done" << endl;
		for (int j = 0; j < Y; ++j)
			intermediates[j] += rot[j];
		cout << "   add done" << endl;
	}
	cout << "C done" << endl;
	for (auto& ctxt: intermediates) user.printDecrypted(ctxt);

	for (auto& ctxt: intermediates)
	{
		cout << "For each ciphertext..." << endl;
		Ctxt_vec final_res;
		for (int i = 0; i < max_packed; ++i) 
		{
			HELIB_NTIMER_START(nslot);
			vector<ZZX> p1_j(nslots);
			for (int k = 0; k < exp_len; ++k)
				p1_j[i * exp_len + k] = ZZX(1);
			HELIB_NTIMER_START(timer_e1j_encrypt);
			Ctxt e1_j(comparator.m_pk);
			comparator.m_context.getView().encrypt(e1_j, p1_j);
			HELIB_NTIMER_STOP(timer_e1j_encrypt);
			Ctxt extract = e1_j;
			extract *= ctxt;
			Ctxt extract_copy = extract;
			Ctxt TS_1 = extract;
			for (int j = 1; j < max_packed; ++j)
			{
				shift(extract, -1 * exp_len);
				TS_1 += extract;
			}
			// for (int j = i; j >= 0; j--)
			// {
			//     shift(extract_copy, -1 * exp_len);
			//     TS_1 += extract_copy;
			// }
			cout << "   Extract and TS1" << endl;

			Ctxt_vec EQ_Extract;
			EQ_Extract.reserve(q.dest.size());
			Ctxt_vec ts1_p;
			comparator.extract_mod_p(ts1_p, TS_1);
			for (int j = 0; j < db[0].size(); ++j)
			{
				Ctxt_vec c_uid_p;
				Ctxt_vec ctxt_eq_p;
				comparator.extract_mod_p(c_uid_p, db[0][j]);
				for (long iCoef = 0; iCoef < D; iCoef++)
				{
					Ctxt eql = ts1_p[iCoef];
					eql -= c_uid_p[iCoef];
					//equality circuit
					comparator.mapTo01_subfield(eql, 1);
					
					eql.negate();
					eql.addConstant(ZZ(1));
					ctxt_eq_p.push_back(eql);
				}
				Ctxt ctxt_eq = ctxt_eq_p[D-1];
				for (long iCoef = D - 2; iCoef >= 0; iCoef--)
					ctxt_eq *= ctxt_eq_p[iCoef];
				if(exp_len != 1)
				{
					comparator.shift_and_mul(ctxt_eq, 0);
					comparator.batch_shift_for_mul(ctxt_eq, 0, -1);
				}
				for (int k = 0; k < q.dest.size(); ++k)
				{
					Ctxt tmp = ctxt_eq;
					tmp *= db[q.dest[k]][j];
					if (!j)
						EQ_Extract.push_back(tmp);
					else
						EQ_Extract[k] += tmp;
				}
			}
			cout << "   Equal and Extract" << endl;

			for (int k = 0; k < q.dest.size(); ++k)
			{
				Ctxt TS_left = EQ_Extract[k];
				Ctxt TS_right = EQ_Extract[k];
				for (int j = 0; j < max_packed - 1; ++j)
				{
					shift(TS_left, -1 * exp_len);
					EQ_Extract[k] += TS_left;
				}
				EQ_Extract[k] *= e1_j;
			}
			cout << "   TS2 and extract" << endl;

			if (!i) //if first
				for (auto& ext: EQ_Extract) final_res.push_back(ext);
			else
				for (int k = 0; k < q.dest.size(); ++k) final_res[k] += EQ_Extract[k];
			HELIB_NTIMER_STOP(nslot);
			helib::printNamedTimer(cout, "nslot");
			cout << "nslot" << endl;
		}
		

		for (int k = 0; k < q.dest.size(); ++k) result[k].push_back(final_res[k]);
	}
	HELIB_NTIMER_STOP(timer_Query);

	user.printCtxtMat(result);

    helib::printNamedTimer(std::cout << std::endl, "timer_Context");
    helib::printNamedTimer(std::cout, "timer_SecKey");
    helib::printNamedTimer(std::cout, "timer_PubKey");
    helib::printNamedTimer(std::cout, "timer_Encrypt_DB");
    helib::printNamedTimer(std::cout, "timer_IndexFile");
	helib::printNamedTimer(std::cout, "timer_Query");

    return 0;
}



