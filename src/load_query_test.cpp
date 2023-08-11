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
	helib::printNamedTimer(cout, "timer_comparator");

	

	/*Secret key is contained in this class. Be carefull! */
    USER user = USER(comparator, contx, public_key, secret_key, verbose); //pass secret key only to user
	HEQuery q1(public_key);
	user.ConstructQuery(q1, 15, EQ, 0, {0, 1, 2});


	/************************* HE QUERY SERIALIZATION
	ofstream q1file;
	q1file.open("q1file", std::ios::out);
	if (q1file.is_open()) {
		// Write the context to a file
		q1.writeTo(q1file);
		// Close the ofstream
		q1file.close();
	} else {
		throw std::runtime_error("Could not open file 'q1file'.");
	}
	cout << q1 << endl;
	user.printDecryptedINT(q1.query);
	user.printDecryptedINT(q1.Q_type.first);
	user.printDecryptedINT(q1.Q_type.second);
	cout << endl;

	ifstream q2file;
	HEQuery q2(public_key);
	q2file.open("q1file");
	if (q2file.is_open()) {
		// Read in the context from the file
		q2.read(q2file);
		// Close the ifstream
		q2file.close();
	} else {
		throw std::runtime_error("Could not open file 'q1file'.");
	}
	cout << q2 << endl;
	user.printDecryptedINT(q2.query);
	user.printDecryptedINT(q2.Q_type.first);
	user.printDecryptedINT(q2.Q_type.second);
	return 0;
	***************************HE QUERY SERIALIZATION END */

	// Ctxt_mat db;
	// vector<string> headers;
	db_filename = "../db/" + db_filename + ".csv";
	user.createPtxtIndexFile(db_filename);
	// if (verbose)
	// 	user.getPtxtIndexFile().printIndexFile();
	// HELIB_NTIMER_START(timer_Encrypt_DB);
	// user.csvToDB(db, db_filename, headers);
	// HELIB_NTIMER_STOP(timer_Encrypt_DB);
    // cout << endl;
	

	// if (verbose)
	// {
	// 	for (auto& h:headers)
	// 		cout << "\nhead: " << h;
	// 	cout << endl;
	// 	user.printCtxtMatINT(db);
	// }
	

	// HELIB_NTIMER_START(timer_IndexFile);
	CtxtIndexFile indFile;
	user.createCtxtIndexFile(indFile);
	
	// HELIB_NTIMER_STOP(timer_IndexFile);

	/**************************INDEXFILE SERIALIZATION******************/
	ofstream q1file;
	q1file.open("q1file", std::ios::out);
	if (q1file.is_open()) {
		// Write the context to a file
		indFile.writeTo(q1file);
		// Close the ofstream
		q1file.close();
	} else {
		throw std::runtime_error("Could not open file 'q1file'.");
	}
	cout << indFile << endl;
	for (auto& pair: indFile.getIndexFile())
	{
		cout << "Colname: " << pair.first << endl;
		user.printCtxtVecINT(pair.second.keys());
		user.printCtxtMatINT(pair.second.uids());
		cout << endl;
	}
	cout << endl;

	ifstream q2file;
	CtxtIndexFile outFile;
	q2file.open("q1file");
	if (q2file.is_open()) {
		// Read in the context from the file
		outFile.read(q2file, public_key);
		// Close the ifstream
		q2file.close();
	} else {
		throw std::runtime_error("Could not open file 'q1file'.");
	}
	cout << outFile << endl;
	for (auto& pair: outFile.getIndexFile())
	{
		cout << "Colname: " << pair.first << endl;
		user.printCtxtVecINT(pair.second.keys());
		user.printCtxtMatINT(pair.second.uids());
		cout << endl;
	}
	cout << endl;
	return 0;
	/**************************INDEXFILE SERIALIZATION END******************/

	ZZX test1 = ZZX(INIT_MONO, 0, 0);
	ZZX test2 = ZZX(INIT_MONO, 0, 0);
	for (int i =0; i < 4; ++i) 
		test1 += ZZX(INIT_MONO, i, 1);
	for (int i =0; i < 15; ++i) 
		test2 += ZZX(INIT_MONO, i, 1);
	
	vector<ZZX> test11ptxt(contx.getNSlots());
	vector<ZZX> test12ptxt(contx.getNSlots());
	vector<ZZX> test21ptxt(contx.getNSlots());
	vector<ZZX> test22ptxt(contx.getNSlots());
	test11ptxt[1] = test1;
	test21ptxt[0] = test2;
	for (auto& z: test12ptxt) z = test1;
	for (auto& z: test22ptxt) z = test2;

	Ctxt test11ctxt(public_key);
	Ctxt test12ctxt(public_key);
	Ctxt test21ctxt(public_key);
	Ctxt test22ctxt(public_key);
	contx.getView().encrypt(test11ctxt, test11ptxt);
	contx.getView().encrypt(test12ctxt, test12ptxt);
	contx.getView().encrypt(test21ctxt, test21ptxt);
	contx.getView().encrypt(test22ctxt, test22ptxt);

	Ctxt add = test11ctxt;
	vector<ZZX> decrypted_cipher(contx.getNSlots());
	contx.getView().decrypt(test12ctxt, secret_key, decrypted_cipher);
	cout << "Enc( ";
	for (auto & zzx: decrypted_cipher)
		printZZX(cout, zzx);
	cout << " ), " << endl;

	ZZX mask_zzx = ZZX(INIT_MONO, 1, 1);
	vector<ZZX> maskvec(contx.getNSlots());
	for (auto& z: maskvec) z = mask_zzx;
	// Ctxt maskctxt(public_key);
	// contx.getView().encrypt(maskvec, maskctxt);
	PtxtArray maskptxt(contx);
	maskptxt.load(mask_zzx);
	cout << maskptxt << endl;
	cout << "HERE" << endl;
	
	// test12ctxt *= maskctxt;
	test12ctxt *= maskptxt;
	decrypted_cipher.clear();
	contx.getView().decrypt(test12ctxt, secret_key, decrypted_cipher);
	cout << "Enc( ";
	for (auto & zzx: decrypted_cipher)
		printZZX(cout, zzx);
	cout << " ), " << endl;

	add += test11ctxt;
	decrypted_cipher.clear();
	contx.getView().decrypt(add, secret_key, decrypted_cipher);
	cout << "Enc( ";
	for (auto & zzx: decrypted_cipher)
		printZZX(cout, zzx);
	cout << " ), " << endl;
	return 1;

	ofstream test11file;
	test11file.open("test11file", std::ios::out);
	if (test11file.is_open()) {
		// Write the context to a file
		test11ctxt.writeTo(test11file);
		// Close the ofstream
		test11file.close();
	} else {
		throw std::runtime_error("Could not open file 'test11file'.");
	}

	ofstream test12file;
	test12file.open("test12file", std::ios::out);
	if (test12file.is_open()) {
		// Write the context to a file
		test12ctxt.writeTo(test12file);
		// Close the ofstream
		test12file.close();
	} else {
		throw std::runtime_error("Could not open file 'test12file'.");
	}

	ofstream test21file;
	test21file.open("test21file", std::ios::out);
	if (test21file.is_open()) {
		// Write the context to a file
		test21ctxt.writeTo(test21file);
		// Close the ofstream
		test21file.close();
	} else {
		throw std::runtime_error("Could not open file 'test21file'.");
	}

	ofstream test22file;
	test22file.open("test22file", std::ios::out);
	if (test22file.is_open()) {
		// Write the context to a file
		test22ctxt.writeTo(test22file);
		// Close the ofstream
		test22file.close();
	} else {
		throw std::runtime_error("Could not open file 'test22file'.");
	}

	// vector<ZZX> decrypted_cipher(contx.getNSlots());
	// contx.getView().decrypt(test11ctxt, secret_key, decrypted_cipher);
	// cout << "Enc( ";
	// for (auto & zzx: decrypted_cipher)
	// 	printZZX(cout, zzx);
	// cout << " ), " << endl;

	// decrypted_cipher.clear();
	// contx.getView().decrypt(test12ctxt, secret_key, decrypted_cipher);
	// cout << "Enc( ";
	// for (auto & zzx: decrypted_cipher)
	// 	printZZX(cout, zzx);
	// cout << " ), " << endl;

	// decrypted_cipher.clear();
	// contx.getView().decrypt(test21ctxt, secret_key, decrypted_cipher);
	// cout << "Enc( ";
	// for (auto & zzx: decrypted_cipher)
	// 	printZZX(cout, zzx);
	// cout << " ), " << endl;

	// decrypted_cipher.clear();
	// contx.getView().decrypt(test22ctxt, secret_key, decrypted_cipher);
	// cout << "Enc( ";
	// for (auto & zzx: decrypted_cipher)
	// 	printZZX(cout, zzx);
	// cout << " ), " << endl;
	return 1;
}