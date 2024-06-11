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
	const struct BGV_param HDB_Param = TOY_HDB;
	bool verbose = false;

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
	string db_filename = "../db/insurance_int_encoded.csv";
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
	

	// HELIB_NTIMER_START(timer_IndexFile);
	// CtxtIndexFile indFile;
	// user.createCtxtIndexFile(indFile);
	// HELIB_NTIMER_STOP(timer_IndexFile);
	
	// cout << "created index file" << endl;
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



