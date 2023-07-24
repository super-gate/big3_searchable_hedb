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

	const struct BGV_param HDB_Param = std128 ? STD128_HDB : MakeBGVParam(p, d, m, bits, c, l, scale, r);

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
		user.printCtxtMatINT(db);
	}
	cout << contx.getView().getPAlgebra().numOfGens() << endl;
	return 1;
	

	HELIB_NTIMER_START(timer_IndexFile);
	CtxtIndexFile indFile;
	user.createCtxtIndexFile(indFile);
	HELIB_NTIMER_STOP(timer_IndexFile);
	Ctxt test = db[0][0];
	long n = contx.getView().size();
	cout << "n: " << n << endl;

	Ctxt orig = test;

	long k = NTL::NumBits(n);
	cout << "k: " << k << endl;
	long e = -1;

	for (long i = k - 2; i >= 0; i--) {
		cout << "	e: " << e << endl;
		cout << "	i: " << i << endl;
		cout << " 	bit(n,i): " << NTL::bit(n, i) << endl;
		Ctxt tmp1 = test;
		rotate(tmp1, e);
		test += tmp1; // ctxt = ctxt + (ctxt >>> e)
		e = 2 * e;

		if (NTL::bit(n, i)) {
			Ctxt tmp2 = orig;
			rotate(tmp2, e);
			test += tmp2; // ctxt = ctxt + (orig >>> e)
							// NOTE: we could have also computed
							// ctxt =  (ctxt >>> e) + orig, however,
							// this would give us greater depth/noise
			e -= 1;
		}
	}
	// for (int neg = -1; neg >= -50; neg--)
	// {
	// 	HELIB_NTIMER_START(timer_rotate_neg);
	// 	shift(test, neg);
	// 	// user.printDecryptedINT(test);
	// 	HELIB_NTIMER_STOP(timer_rotate_neg);
	// 	cout << "neg: " << neg;
	// 	helib::printNamedTimer(std::cout, "timer_rotate_neg");
	// }
	// HELIB_NTIMER_START(timer_rotate_neg);
	// shift(test, -3117);
	// user.printDecryptedINT(test);
	// HELIB_NTIMER_STOP(timer_rotate_neg);
	// helib::printNamedTimer(std::cout, "timer_rotate_neg");
	// HELIB_NTIMER_START(timer_rotate);
	// shift(test, 1);
	// user.printDecryptedINT(test);
	// HELIB_NTIMER_STOP(timer_rotate);
	// HELIB_NTIMER_START(timer_shift);
	// shift(test, 1);
	// user.printDecryptedINT(test);
	// HELIB_NTIMER_STOP(timer_shift);
	Ctxt rot = test;
	Ctxt custom = test;
	user.printDecryptedINT(test);
	HELIB_NTIMER_START(timer_custom_TS);
	for (int i = 1; i < contx.getNSlots(); ++i)
	{
		if (i%100 == 0) 
			{cout << i << endl; printNamedTimer(cout, "rotate");}
		HELIB_NTIMER_START(rotate);
		rotate(rot, -1);
		HELIB_NTIMER_STOP(rotate);
		custom += rot;
	}
	user.printDecryptedINT(custom);
	HELIB_NTIMER_STOP(timer_custom_TS);
	helib::printNamedTimer(std::cout, "timer_custom_TS");
	Ctxt test_copy = test;
	HELIB_NTIMER_START(timer_total_sum);
	totalSums(test_copy);
	user.printDecryptedINT(test_copy);
	HELIB_NTIMER_STOP(timer_total_sum);
	// helib::printNamedTimer(std::cout, "timer_rotate");
	// helib::printNamedTimer(std::cout, "timer_shift");
    helib::printNamedTimer(std::cout, "timer_total_sum");
    return 0;
}



