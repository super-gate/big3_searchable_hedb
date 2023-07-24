#include <stdio.h>
#include <iostream>
#include <sstream>

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

int main() {
	while (true)
	{
		long p;
		cout << "input p: " << endl;
		cin >> p;
		stringstream ss;
		ss << "nslots_" << to_string(p) << ".txt";
		string s = ss.str();
		ofstream fout(s);
		for (long m = 10000; m < 150000; ++m)
		{
			if (GCD(p, m) != 1) continue;
			long nslots = findNSlots(p, m);
			if (nslots < 100) continue;
			fout << "m: " << m << " nslots: " << nslots << "\n";
		}
		fout.close();
	}

    return 0;
}



