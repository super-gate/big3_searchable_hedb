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
	HELIB_NTIMER_START(timer_comparator);
	Comparator comparator(contx, type, HDB_Param.d, HDB_Param.expansion_len, public_key, false); // secret key deleted. only public key remained
	HELIB_NTIMER_STOP(timer_comparator);
	cout << "comparator created" << endl;

	/*Secret key is contained in this class. Be carefull! */
	HELIB_NTIMER_START(timer_user);
    USER user = USER(comparator, contx, public_key, secret_key, verbose); //pass secret key only to user
	HELIB_NTIMER_STOP(timer_user);
	cout << "user created" << endl;

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
		user.printCtxtMatINT(db);
		user.printCtxtMatZZX(db);
	}
	

	HELIB_NTIMER_START(timer_IndexFile);
	CtxtIndexFile indFile;
	// user.createCtxtIndexFile(indFile);
	HELIB_NTIMER_STOP(timer_IndexFile);
	
	cout << "created index file" << endl;
	/*SERVER SIDE */
	HELIB_NTIMER_START(timer_server);
    SERVER server = SERVER(comparator, db, indFile, verbose);
	HELIB_NTIMER_STOP(timer_server);
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
	
	while(true)
	{
		cout << "\nSELECT (DEST) \nFROM (SOURCE) \nWHERE (SOURCE) (QUERYTYPE) (INPUT)\n" << endl;
		Q_TYPE_t queryType;
		string str;
		while(true)
		{
			cout<<"Select Query Type (eq, lt, leq):";
			cin>>str;
			if(str == "eq")
			{
				queryType = EQ;
				str = "=";
				break;
			}
			else if(str == "lt")
			{
				queryType = LT;
				str = "<";
				break;
			}
			else if(str == "leq")
			{
				queryType = LEQ;
				str = "<=";
				break;
			}
		}
		cout << "\nSELECT (DEST) \nFROM (SOURCE) \nWHERE (SOURCE) " << str << " (INPUT)\n" << endl;

		unsigned long max = user.max();
		long input;
		while(true)
		{
			cout << "Input Query integer: ";
			cin>>input;
			if(input < max)
			{
				break;
			}
		}
		cout << "\nSELECT (DEST) \nFROM (SOURCE) \nWHERE (SOURCE) " << str << " " << input << "\n" << endl;

		cout << "Columns:" << endl;
		for (int h = 0; h < headers.size(); ++h) cout << "[" << h << "]: " << headers[h] << endl;
		cout << endl;

		vector<long> dest; //TODO: try more dest columns
		long source;
		
		while(true)
		{
			cout << "Input source column index: ";
			cin >> source;
			if (source < headers.size()) break;
		}
		cout << "\nSELECT (DEST) \nFROM " << headers[source] << "\nWHERE " << headers[source] << " " << str << " " << input << "\n" << endl;

		string sdest;
		while(true)
		{
			cout << "Choose DEST column indexes (* for all, enter 'b' to break): ";
			cin >> sdest;
			if (sdest == "b")
			{
				if (!dest.empty()) break;
				continue;
			}
			if (!dest.empty() && sdest == "*") 
			{
				for (int h = 0; h < headers.size(); ++h) dest.push_back(h);
				break;
			}
			int destind = stoi(sdest);
			if (destind >= headers.size()) continue;
			dest.push_back(destind);
		}
		cout << "Final Query:" << endl;
		cout << "\nSELECT ";
		for (auto& d : dest) cout << headers[d] << ", ";
		cout << "\nFROM " << headers[source] << "\nWHERE " << headers[source] << " " << str << " " << input << endl;
		cout << endl;

		HEQuery q(public_key);
		user.ConstructQuery(q, input, queryType, source, dest);
		string qtype;
		while(true)
		{
			cout << "Choose query type: \n[0]: Regular Query\n[1]: ExtensionField Query\n[2]: Index Query" << endl;
			cin >> qtype;
			Ctxt_mat result;
			HELIB_NTIMER_START(timer_Query);
			switch(stoi(qtype))
			{
				case 0:
					server.Query(q, result);
					break;
				case 1:
					server.QueryExtensionField(q, result);
					break;
				case 2:
					server.QueryWithIndex(q, result);
					break;
				default:
					cout << "Invalid" << endl;
					break;
			}
			HELIB_NTIMER_STOP(timer_Query);

			cout <<"\nResults: " << endl;
			user.printCtxtMatINT(result, true);
			// user.printCtxtMatZZX(result);

			helib::printNamedTimer(std::cout << std::endl, "timer_Context");
			helib::printNamedTimer(std::cout, "timer_SecKey");
			helib::printNamedTimer(std::cout, "timer_PubKey");
			helib::printNamedTimer(std::cout, "timer_comparator");
			helib::printNamedTimer(std::cout, "timer_user");
			helib::printNamedTimer(std::cout, "timer_server");
			helib::printNamedTimer(std::cout, "timer_Encrypt_DB");
			helib::printNamedTimer(std::cout, "timer_IndexFile");
			helib::printNamedTimer(std::cout, "nslot");
			helib::printNamedTimer(std::cout, "timer_Query");
			cout << "\nPerform another query? (y/n)" << endl;
			string s;
			cin >> s;
			if (s == "n") break;
		}
	}

    return 0;
}



