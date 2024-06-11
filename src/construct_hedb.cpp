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
#include <optional>

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

	const struct BGV_param HDB_Param = std128 ? MakeBGVParam(p, d, m, bits, c, l, scale, r): TOY_HDB;

	// Create Context
	HELIB_NTIMER_START(timer_Context);
    Context* contx = MakeBGVContextPtr(HDB_Param); //TODO: Test Parameters
	HELIB_NTIMER_STOP(timer_Context);
    // cout << "Q size: " << contx.logOfProduct(contx.getCtxtPrimes())/log(2.0) << endl;
    // cout << "Q*P size: " << contx.logOfProduct(contx.fullPrimes())/log(2.0) << endl;
    // cout << "Security: " << contx.securityLevel() << endl;    
    // cout<<"///////////////////////////////////"<<endl;
	// contx.getZMStar().printout();
	// cout<<endl;
	// cout<<"/////////////////////////////////////"<<endl;

	/*****************************************Storage************************************************/
	//Create User
	USER user(verbose);

	//Generate Keys
	pair<PubKey, SecKey> keys = user.generateKeys(contx, HDB_Param);
	PubKey pk = keys.first;
	// cout << pk.isCKKS() << endl;

	//Encrypt and Save DB
	string db_path = "../db/" + db_filename + ".csv";
	Ctxt_mat db;
	vector<string> headers;
	CtxtIndexFile indFile;
	user.EncryptData(db_path, HDB_Param, db, headers, indFile, true);

	//send to REE (needs to be implemented)
	//deserialized DB Contx, Pubkey in REE
	//in another script where it receives the serialized DB, Context, Pubkey... and indFile if applicable
	SERVER server(verbose);
	cout << "created Server" << endl;
	optional<CtxtIndexFile> indOpt = indFile.empty() ? nullopt : optional<CtxtIndexFile>(indFile);
	//Save DB in REE
	server.SaveDB(db_filename, HDB_Param, *contx, pk, db, indOpt);
	cout << "Save DB Complete" << endl;

	return 1;
}