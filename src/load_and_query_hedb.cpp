#include <stdio.h>
#include <iostream>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/debugging.h>

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
			"Qualified name for the csv database filename(default: insurance_int_encoded)");
	amap.toggle().arg("-v", verbose, "Toggle verbose", "");

	amap.toggle().arg("-std", std128, "Toggle to just use default standard128 params with all default settings", "");
	amap.parse(argc, argv);

	const struct BGV_param HDB_Param = std128 ? MakeBGVParam(p, d, m, bits, c, l, scale, r) : TOY_HDB;

	USER user(verbose);
	string db_path = "../db/" + db_filename + ".csv";
	vector<string> headers(0);
	user.getCSVHeaders(db_path, headers);
	SERVER server(verbose);
	while(true)
	{
		cout << "Fill in the Query:\nSELECT (OUTPUT_COLUMNS) \nFROM " << db_filename << "\nWHERE (QUERY_COLUMN) (QUERY_TYPE) (INPUT_QUERY)\n" << endl;

		cout << "Columns:" << endl;
		for (int h = 0; h < headers.size(); ++h) cout << "[" << h << "]: " << headers[h] << endl;
		cout << endl;

		vector<long> dest; //TODO: try more dest columns
		long source;
		
		while(true)
		{
			cout << "Input QUERY_COLUMN index: ";
			cin >> source;
			if (source < headers.size()) break;
		}
		string sdest;
		while(true)
		{
			cout << "Choose OUTPUT_COLUMNS indexes (* for all, enter 'b' to break): ";
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

		Q_TYPE_t queryType;
		string str;
		while(true)
		{
			cout<<"Select QUERYTYPE (eq, lt, leq): ";
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

		unsigned long max = user.max();
		long input;
		while(true)
		{
			cout << "Input INPUT_QUERY (integer): ";
			cin>>input;
			if(input < max)
			{
				break;
			}
		}
		
		cout << "Final Query:" << endl;
		cout << "\nSELECT ";
		for (auto& d : dest) cout << headers[d] << ", ";
		cout << "\nFROM " << db_filename << "\nWHERE " << headers[source] << " " << str << " " << input << endl;
		cout << endl;

		HEQuery* query = user.ConstructQuery(HDB_Param, input, queryType, source, dest);
		stringstream qstream;
		query->writeTo(qstream);
		qstream.seekg(0, std::ios::beg);

		Q_MODE mode = NORMAL;
		string qtype;

		cout << "Choose query type: \n[0]: Regular Query\n[1]: ExtensionField Query\n[2]: Index Query" << endl;
		cin >> qtype;
		switch(stoi(qtype))
		{
			case 0:
				mode = NORMAL;
				break;
			case 1:
				mode = EXTF;
				break;
			case 2:
				mode = IND;
				break;
			default:
				cout << "Invalid" << endl;
				break;
		}
		
		Ctxt_mat result;
		server.ProcessQuery(db_filename, HDB_Param, mode, qstream, result);
		cout << "\n\n" << endl;

		//send result to user
		user.printQueryResult(HDB_Param, result, mode);

		cout << "\nPerform another query? (y/n)" << endl;
		string s;
		cin >> s;
		if (s == "n") break;
	}
	return 1;
}