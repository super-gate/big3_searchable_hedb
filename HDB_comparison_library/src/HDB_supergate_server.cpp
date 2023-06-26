#include<stdio.h>
#include<iostream>

#include <helib/debugging.h>
#include "HDB_supergate_server.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

using namespace HDB_supergate_;
using namespace helib;
using namespace std;
using namespace he_cmp;
using namespace NTL;

namespace HDB_supergate_server_{
    /* Construction */
    SERVER::SERVER (Comparator& comparator,
					Ctxt_mat& db,
					CtxtIndexFile& indFile,
					bool v) : comparator(comparator), 
							  DB(db), 
							  IndexFile(indFile),
							  Col(db.size()),
							  Row(db[0].size()),
							  verbose(v) {};
					
	void SERVER::Query(HEQuery& q, Ctxt_mat& res)
	{
		res.resize(q.dest.size()); // resize result so we have #dest rows
		for (auto& row: res) row.reserve(Row);

		Ctxt_mat less_mod_ctxt_arr, eq_mod_ctxt_arr;
		less_mod_ctxt_arr.resize(Row);
		eq_mod_ctxt_arr.resize(Row);
		for (auto& row: less_mod_ctxt_arr) row.reserve(comparator.m_slotDeg);
		for (auto& row: eq_mod_ctxt_arr) row.reserve(comparator.m_slotDeg);

		for (unsigned long i = 0; i < Row; ++i)
		{
			//UNI
			Ctxt z_ctxt = DB[q.source][i];
			z_ctxt -= q.query;
			vector<Ctxt> mod_p_coefs;
			comparator.extract_mod_p(mod_p_coefs, z_ctxt);
			
			for(unsigned long iCoef = 0; iCoef < comparator.m_slotDeg; ++iCoef)
			{
				Ctxt ctxt_less = Ctxt(comparator.m_pk);
				Ctxt ctxt_eq = Ctxt(comparator.m_pk);
				comparator.evaluate_univar_less_poly(ctxt_less, ctxt_eq, mod_p_coefs[iCoef]);
				less_mod_ctxt_arr[i].emplace_back(ctxt_less);
				ctxt_eq.negate();
				ctxt_eq.addConstant(ZZ(1));
				eq_mod_ctxt_arr[i].emplace_back(ctxt_eq);
			}
			Ctxt ctxt_less = less_mod_ctxt_arr[i][comparator.m_slotDeg - 1];
			Ctxt ctxt_eq = eq_mod_ctxt_arr[i][comparator.m_slotDeg - 1];
			for(long iCoef = comparator.m_slotDeg - 2; iCoef >= 0; iCoef--)
			{
				Ctxt tmp = ctxt_eq;
				tmp *= less_mod_ctxt_arr[i][iCoef];
				ctxt_less += tmp;

				ctxt_eq *= eq_mod_ctxt_arr[i][iCoef];
			}
			Ctxt eq_final = ctxt_eq;

			if(comparator.m_expansionLen != 1)
			{
				comparator.shift_and_mul(ctxt_eq, 0);
				comparator.batch_shift_for_mul(ctxt_eq, 0, -1);

				ctxt_less *= ctxt_eq;
				comparator.shift_and_add(ctxt_less, 0);
			}
			Ctxt less_final = ctxt_less;
			eq_final *= q.Q_type.first;
			less_final *= q.Q_type.second;

			Ctxt query_final = eq_final;
			query_final += less_final;

			for (unsigned long j = 0; j < q.dest.size(); ++j)
			{
				Ctxt res_final = query_final;
				res_final *= DB[q.dest[j]][i];
				res[j].emplace_back(res_final);
			}
		}
	}

	//can only do EQ query right now
	void SERVER::QueryWithIndex(HEQuery& q, Ctxt_mat& res)
	{
		CtxtIndex& Index = IndexFile.find(q.source);
		res.resize(q.dest.size()); // resize result so we have #dest rows
		for (auto& row: res) row.reserve(Index.getY());

		
	}

} 

