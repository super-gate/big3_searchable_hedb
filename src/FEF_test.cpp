#include <stdio.h>
#include <iostream>
#include <fstream>

#include <unistd.h>

#include <helib/helib.h>
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

void readAnswer(vector<vector<unsigned long>>& ans, string fname)
{
	ifstream f;
	f.open(fname);
	string line;
	unsigned long uid, c1, c2, c3;
	getline(f, line);
	while (getline(f, line))
	{
		sscanf(line.c_str(), "%ld,%ld,%ld,%ld", &uid, &c1, &c2, &c3);
		if (c1 != 62) continue;
		ans.push_back({uid, c3});
	}
}

int main() {
	vector<vector<unsigned long>> ans;
	string db_filename = "../db/64bit.csv";
	readAnswer(ans, db_filename);

	ifstream params;
	params.open("./params.txt");
	string param;
	long p, m, d=6, exp_len=3, bits=500, c=3, r=1, scale=6, total=217;

	ofstream resultFile;
	resultFile.open("./results.txt", ios::out);
	while (getline(params, param))
	{
		sscanf(param.c_str(), "%ld,%ld", &p, &m);
		BGV_param bgv_param = MakeBGVParam(p, d, m, bits, exp_len, c, scale, r);
		const Context contx = MakeBGVContext(bgv_param);

		SecKey sk(contx);
		sk.GenSecKey();
		if (exp_len > 1)
		{
			if (contx.getZMStar().numOfGens() == 1)
			{
				std::set<long> automVals;
				long e = 1;
				long ord = contx.getZMStar().OrderOf(0);
				bool native = contx.getZMStar().SameOrd(0);
				if(!native)
					automVals.insert(contx.getZMStar().genToPow(0, -ord));
				while (e < exp_len){
					long atm = contx.getZMStar().genToPow(0, ord-e);
					automVals.insert(atm);
					e <<=1;
				}
				addTheseMatrices(sk, automVals);
			}
			else
			{
			addSome1DMatrices(sk);
			}
		}

		if (d > 1)
			addFrbMatrices(sk);
		
		PubKey pk(sk);

		Comparator comp(contx, UNI, d, exp_len, pk, false);
		USER user(comp, contx, pk, sk, false);
		Ctxt_mat db;
		vector<string> headers;
		user.csvToDB(db, db_filename, headers);

		CtxtIndexFile indFile;
		SERVER server(comp, db, indFile, false);

		HEQuery q(pk);
		user.ConstructQuery(q, 62, EQ, 1, {0, 3});

		int counter = 0, orig, ext;

		while (counter++ < 2)
		{
			HELIB_NTIMER_START(timer_query);
			Ctxt_mat result;
			server.Query(q, result);
			orig = result[0].size();
			HELIB_NTIMER_STOP(timer_query);
			//check validity

			result.clear();
			HELIB_NTIMER_START(timer_ext_query);
			server.QueryExtensionField(q, result);
			ext = result[0].size();
			HELIB_NTIMER_STOP(timer_ext_query);
			//check validity

			
		}
		resultFile << "p: " << p << "m, " << m << ", orig: " << orig << ", ext: " << ext << "\n";
		printNamedTimer(resultFile, "timer_query");
		printNamedTimer(resultFile, "timer_ext_query");
		resultFile << "----------------------------------------\n" << endl;
		resetAllTimers();

		//print timers to file

		if (m == 29539) break;
	}


	return 0;
}