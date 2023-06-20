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
	string db_filename = "db.csv";  // db filename

	bool verbose = false;			// if true lots of debug info
	bool std128 = false;			// if true, just use HDB_STD128 params, else use the default+user params

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
			"Qualified name for the database filename");
	amap.toggle().arg("-v", verbose, "Toggle verbose", "");
	amap.toggle().arg("-std", std128, "Toggle to just use standard128 params", "");
	amap.parse(argc, argv);

	const struct BGV_param HDB_Param = std128 ? STD128_HDB : MakeBGVParam(p, d, m, bits, c, l, scale, r);
	Ctxt_mat mat;
	vector<string> headers;
	cout << "HI" << endl;
	csvToDB(mat, "../db/insurance_int_encoded.csv", headers);
	for (auto& h:headers)
		cout << "\nhead: " << h;
	cout << endl;
	cout << "BYE" << endl;
	csvToDB(mat, "../db/insurance_int_encoded.csv");
	return 1;
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
	PubKey public_key(secret_key);
	
	CircuitType type = UNI; //Fixed at UNI
	
	Comparator comparator(contx, type, HDB_Param.d, HDB_Param.expansion_len, public_key, false); // secret key deleted. only public key remained

	/*Secret key is contained in this class. Be carefull! */
    USER user = USER(comparator, secret_key); //pass secret key only to user
	/*SERVER SIDE */   
    SERVER server = SERVER(comparator);

	/*
	 * 1. readCSV() => reads csv file and populates plaintext DB
	 * 2. DB is encrypted and stored in server
	 * 3. makeIndex() => creates index file according to algorithm
	 * 4. Index file is encrypted and stored in server
	 * 5. SERVER::query() => params: query_col_index, query_ctxt, query_type, dest_query_indexes, returns: dest_query_result
	 * 6. USER::decryptResult() => user decrypts result
	 * 7. Make user in a loop so that we can query multiple times into one server (so that we don't have to instantiate everything for each query)
	 */

    long unsigned num_db_element;
    long unsigned num_db_category;
    long unsigned max_element;
	std::vector<std::vector<int64_t>> database;

    // server.SetDB(db_filename, num_db_element, max_element, num_db_category);
	// if (verbose)
	// 	server.ShowDB();

    /*USER SIDE, Make the query and send it to the server */

    /*0: exact, 1: less then, 2: min */
    string str;

    Q_TYPE_t types;


	while(true)
	{
		cout<<"the type has to be one of (eq, lt, el)."<<endl;
		cout<<"input type: ";
		cin>>str;
		if(str == "eq")
		{
			types = EQ;
			break;
		}
		else if(str == "lt")
		{
			types = LT;
			break;
		}
		else if(str == "el")
		{
			types = EL;
			break;
		}
	}

	unsigned long max = user.max();

	int64_t query_id;
	while(true)
	{
		cout<<"maximum int is "<<max - 1<<endl;
		cout<<"input query: ";
		cin>>query_id;

		if(query_id < max)
		{
			break;
		}
	}

	auto ct_query = user.Query(query_id, types);

	/*ct_query_exact is sended to the server. */
    /*SERVER SIDE, / Exact / Less than /(or min)/ calculation and return to the user  */
    
	vector<long> cols;
	server.Response(ct_query, types, cols);

    /*answer is sended to the user */
    //user.ShowRes(datas, less_vector, equal_vector, equal_result, less_result, Row, Category, Element, types);

    cout << "Test End!! " << endl;

    return 0;
}



