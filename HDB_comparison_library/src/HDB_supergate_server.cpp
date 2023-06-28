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
							  verbose(v)
    {
        unsigned long nslots = comparator.m_context.getNSlots();
        unsigned long exp_len = comparator.m_expansionLen;
        unsigned long max_packed = nslots / exp_len;
        for (int i = 0; i < max_packed; ++i)
        {
            vector<ZZX> p1_j(nslots);
            for (int j = 0; j < max_packed; ++j)
            {
                ZZX zo = j == i ? ZZX(1) : ZZX(0);
                for (int k = 0; k < exp_len; ++k)
                    p1_j[j * exp_len + k] = zo;
            }
            Ctxt e1_j(comparator.m_pk);
            comparator.m_context.getView().encrypt(e1_j, p1_j);
            v1_j.push_back(e1_j);
        }
    };
					
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
		unsigned long X = Index.getX();
		unsigned long Y = Index.getY();

		res.resize(q.dest.size()); // resize result so we have #dest rows
		for (auto& row: res) row.reserve(Y);

        unsigned long nslots = comparator.m_context.getNSlots();
        unsigned long exp_len = comparator.m_expansionLen;
        unsigned long D = comparator.m_slotDeg;
        unsigned long max_packed = nslots / exp_len;

        Ctxt_vec q_mod_p;
	    comparator.extract_mod_p(q_mod_p, q.query);

		Ctxt_vec intermediates;
		intermediates.reserve(Y);
		for (auto& k_ctxt: Index.keys()) {
            Ctxt_vec ctxt_eq_p;
            Ctxt_vec k_mod_p;
            comparator.extract_mod_p(k_mod_p, k_ctxt);
            for (long iCoef = 0; iCoef < D; iCoef++)
            {
                Ctxt eql = q_mod_p[iCoef];
                eql -= k_mod_p[iCoef];
                //equality circuit
                comparator.mapTo01_subfield(eql, 1);
                eql.negate();
                eql.addConstant(ZZ(1));
                ctxt_eq_p.push_back(eql);
            }
            Ctxt ctxt_eq = ctxt_eq_p[D-1];
            for(long iCoef = D - 2; iCoef >= 0; iCoef--)
                ctxt_eq *= ctxt_eq_p[iCoef];
            intermediates.emplace_back(ctxt_eq);
	    }

        Ctxt_mat UID_extract = Index.uids(); //copy of the uids table
        for (auto& row: UID_extract)
        {
            for (unsigned long c = 0; c < Index.getY(); ++c)
                row[c] *= intermediates[c];
        }

        intermediates.clear();
        intermediates = UID_extract[0];
        for (int i = 1; i < Index.getX(); ++i) //rotate and add
        {
            Ctxt_vec rot = UID_extract[i];
            for (auto& r: rot) rotate(r, exp_len * i);
            for (int j = 0; j < Index.getY(); ++j)
                intermediates[j] += rot[j];
        }

        for (auto& ctxt: intermediates)
        {
            Ctxt_vec final_res;
            for (int i = 0; i < max_packed; ++i) 
            {
                Ctxt extract = v1_j[i];
                extract *= ctxt;
                Ctxt extract_copy = extract;
                Ctxt TS_1 = extract;
                for (int j = i; j < max_packed - 1; ++j)
                {
                    shift(extract, exp_len);
                    TS_1 += extract;
                }
                for (int j = i; j >= 0; j--)
                {
                    shift(extract_copy, -1 * exp_len);
                    TS_1 += extract_copy;
                }

                Ctxt_vec EQ_Extract;
                EQ_Extract.reserve(q.dest.size());
                Ctxt_vec ts1_p;
                comparator.extract_mod_p(ts1_p, TS_1);
                for (int j = 0; j < DB[0].size(); ++j)
                {
                    Ctxt_vec c_uid_p;
                    Ctxt_vec ctxt_eq_p;
                    comparator.extract_mod_p(c_uid_p, DB[0][j]);
                    for (long iCoef = 0; iCoef < D; iCoef++)
                    {
                        Ctxt eql = ts1_p[iCoef];
                        eql -= c_uid_p[iCoef];
                        //equality circuit
                        comparator.mapTo01_subfield(eql, 1);
                        Ctxt eql_copy = eql;
                        for (int k = 1; k < exp_len; ++k)
                        {
                            shift(eql_copy, 1);
                            eql += eql_copy;
                        }
                        eql.negate();
                        eql.addConstant(ZZ(1));
                        ctxt_eq_p.push_back(eql);
                    }
                    Ctxt ctxt_eq = ctxt_eq_p[D-1];
                    for (long iCoef = D - 2; iCoef >= 0; iCoef--)
                        ctxt_eq *= ctxt_eq_p[iCoef];
                    for (int k = 0; k < q.dest.size(); ++k)
                    {
                        Ctxt tmp = ctxt_eq;
                        tmp *= DB[q.dest[k]][j];
                        if (!j)
                            EQ_Extract.push_back(tmp);
                        else
                            EQ_Extract[k] += tmp;
                    }
                }

                for (int k = 0; k < q.dest.size(); ++k)
                {
                    Ctxt TS_left = EQ_Extract[k];
                    Ctxt TS_right = EQ_Extract[k];
                    for (int j = 0; j < max_packed - 1; ++j)
                    {   
                        shift(TS_right, exp_len);
                        EQ_Extract[k] += TS_right;
                    }
                    for (int j = 0; j < max_packed - 1; ++j)
                    {
                        shift(TS_left, -1 * exp_len);
                        EQ_Extract[k] += TS_left;
                    }
                    EQ_Extract[k] *= v1_j[i];
                }

                if (!i) //if first
                    for (auto& ext: EQ_Extract) final_res.push_back(ext);
                else
                    for (int k = 0; k < q.dest.size(); ++k) final_res[k] += EQ_Extract[k];
            }

            for (int k = 0; k < q.dest.size(); ++k) res[k].push_back(final_res[k]);
        }
    }
} 

