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
							  X(db.size()),
							  Y(db[0].size()),
							  verbose(v) {};
					
	void SERVER::Query(HDB_supergate_::HEQuery& q, Ctxt_mat& res)
	{
		res.resize(q.dest.size()); // resize result so we have #dest rows

		Ctxt_mat less_mod_ctxt_arr, eq_mod_ctxt_arr;
		less_mod_ctxt_arr.resize(Y);
		eq_mod_ctxt_arr.resize(Y);
		for (unsigned long i = 0; i < Y; ++i)
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
	void SERVER::QueryWithIndex(HDB_supergate_::HEQuery&, Ctxt_mat&)
	{
		//
	}

	void SERVER::Response(Ctxt &query, Q_TYPE_t types){
		//get columns from q_cols
		
		long cipher_num = _Row/numbers_size;

		Ctxt_mat less_mod_ctxt_arr;//less than cipher
	    less_mod_ctxt_arr.resize(cipher_num);

		Ctxt_mat eq_mod_ctxt_arr;//equal cipher
        eq_mod_ctxt_arr.resize(cipher_num);
		
		Ctxt_mat data_mod_ctxt_arr;//data modulo cipher
		Ctxt_vec q_mod_ctxt_arr;//query modulo cipher//std::vector<std::vector<Ctxt>> q_mod_ctxt_arr;

		Ctxt_vec z_ctxt_arr;
		Ctxt_mat z_ctxt_mat;
		Ctxt_vec tmp_vec;

		for(int i = 0; i<cipher_num; i++)
		{
			Ctxt tmp(comparator.m_pk);
			less_final.push_back(tmp);
		}

		if(comparator.m_type == BI)
        {   
            comparator.extract_mod_p(tmp_vec, query);
            q_mod_ctxt_arr = tmp_vec;
        }

//UNI
		
		for(int i = 0; i< cipher_num; i++)
		{	
			
			if(comparator.m_type == UNI)
			{
				z_ctxt_arr.push_back(DB[0][i]);
				z_ctxt_arr[i] -= query;
				comparator.extract_mod_p(tmp_vec, z_ctxt_arr[i]);
				z_ctxt_mat.push_back(tmp_vec);
				
				for(unsigned long iCoef = 0; iCoef<comparator.m_slotDeg; iCoef++)
				{
					Ctxt ctxt_tmp = Ctxt(comparator.m_pk);
					Ctxt ctxt_tmp_eq = Ctxt(comparator.m_pk);

					comparator.evaluate_univar_less_poly(ctxt_tmp, ctxt_tmp_eq, z_ctxt_mat[i][iCoef]);

					less_mod_ctxt_arr[i].push_back(ctxt_tmp);
					ctxt_tmp_eq.negate();
					ctxt_tmp_eq.addConstant(ZZ(1));
					eq_mod_ctxt_arr[i].push_back(ctxt_tmp_eq);
				}
			}

//BI
    		if(comparator.m_type == BI)
			{
				comparator.extract_mod_p(tmp_vec, DB[0][i]);
				data_mod_ctxt_arr.push_back(tmp_vec);
		
				for(unsigned long iCoef = 0; iCoef < comparator.m_slotDeg; iCoef++)// 1 block for whole for// 1 block: m_slotDeg
				{	
					Ctxt ctxt_tmp = Ctxt((DB[0][i]).getPubKey());
					comparator.less_than_bivar(ctxt_tmp, data_mod_ctxt_arr[i][iCoef], q_mod_ctxt_arr[iCoef]);//q_mod_ctxt_arr[i][iCoef]
					less_mod_ctxt_arr[i].push_back(ctxt_tmp);//1 mod in a less block
				}
			
				for(unsigned long iCoef = 0; iCoef<comparator.m_slotDeg; iCoef++)
				{
					Ctxt ctxt_z = data_mod_ctxt_arr[i][iCoef];
					ctxt_z -= q_mod_ctxt_arr[iCoef];//q_mod_ctxt_arr[i][iCoef]
					Ctxt ctxt_tmp = Ctxt(ctxt_z.getPubKey());
					comparator.is_zero(ctxt_tmp, ctxt_z);
					eq_mod_ctxt_arr[i].push_back(ctxt_tmp);// eq mod 1 block
				}
			}
			
			Ctxt ctxt_less = less_mod_ctxt_arr[i][comparator.m_slotDeg-1];
			Ctxt ctxt_eq = eq_mod_ctxt_arr[i][comparator.m_slotDeg-1];

			for(long iCoef = comparator.m_slotDeg - 2; iCoef >= 0; iCoef--)
			{
				Ctxt tmp = ctxt_eq;
				tmp.multiplyBy(less_mod_ctxt_arr[i][iCoef]);
				ctxt_less += tmp;

				ctxt_eq.multiplyBy(eq_mod_ctxt_arr[i][iCoef]);
			}

			ctxt_equal.push_back(ctxt_eq);//non modulo equal final

			if(comparator.m_expansionLen == 1)
			{
				less_final.push_back(ctxt_less);//non modulo less ctxt
			}
			else
			{
				comparator.shift_and_mul(ctxt_eq, 0);
				comparator.batch_shift_for_mul(ctxt_eq, 0, -1);

				ctxt_eq.multiplyBy(ctxt_less);
				less_final[i] = ctxt_eq;
				comparator.shift_and_add(less_final[i], 0);
			}
		}
		return;	
    }

	Ctxt_vec SERVER::less_vector() 
	{	
		return less_final;
	}

	Ctxt_vec SERVER::equal_vector()
	{
		return ctxt_equal;
	}
	
	Ctxt_mat SERVER::result_equal()
	{
        unsigned long cipher_num = _Row/numbers_size;

		std::vector<std::vector<Ctxt>> equal_result;
		equal_result.resize(_num_db_category);

		for(unsigned long i = 0; i< _num_db_category; i++)
		{	
			for(unsigned long j = 0; j< cipher_num; j++)
			{
				Ctxt tmp(comparator.m_pk);
				tmp = DB[i][j];
				tmp.multiplyBy(ctxt_equal[j]);
				equal_result[i].push_back(tmp);
			}
		}

		return equal_result;
	}

	Ctxt_mat SERVER::result_less() 
	{
		std::vector<std::vector<Ctxt>> less_result;

		unsigned long cipher_num = _Row/numbers_size;

		less_result.resize(_num_db_category);

        for(unsigned long i = 0; i< _num_db_category; i++)
        {
            for(unsigned long j = 0; j< cipher_num; j++)
            {
                Ctxt tmp(comparator.m_pk);
                tmp = DB[i][j];
                tmp.multiplyBy(less_final[j]);
                less_result[i].push_back(tmp);
            }
        }
		return less_result;
	}

	unsigned long SERVER::row()
	{
		return _Row;
	}

	unsigned long SERVER::category()
	{
		return _num_db_category;
	}

	unsigned long SERVER::element()
	{		
		return _num_db_element;
	}
} 

