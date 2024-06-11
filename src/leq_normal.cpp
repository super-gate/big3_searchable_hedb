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
	string db_filename = "insurance_int_encoded";

	USER user(verbose);
	unsigned long input = 21;
	Q_TYPE_t type = LEQ;
	long source = 1;
	vector<long> dest = {0, 1, 3};
	HEQuery* query = user.ConstructQuery(HDB_Param, input, type, source, dest);
	// cout << query->source << endl;
	// cout << "\n\n" << endl;

	stringstream qstream;
	query->writeTo(qstream);
	qstream.seekg(0, std::ios::beg);

	//send query to server
	Q_MODE mode = NORMAL;
	SERVER server(verbose);
	Ctxt_mat result;
	server.ProcessQuery(db_filename, HDB_Param, mode, qstream, result);
	cout << "\n\n" << endl;
	
	//send result to user
	user.printQueryResult(HDB_Param, result, mode);


    return 0;
}



