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
							  Row(db.size()),
							  Col(db[0].size()),
							  verbose(v),
                              nslots(comparator.m_context.getNSlots()),
                              exp_len(comparator.m_expansionLen),
                              max_packed(nslots / exp_len),
                              D(comparator.m_slotDeg)
    {
        create_all_extraction_masks();
    };

    void SERVER::create_all_extraction_masks() {
        for (int i = 0; i < max_packed; ++i)
            create_extraction_mask(i * exp_len);
    }

    void SERVER::create_extraction_mask(int position)
    {
        vector<long> mask_long(nslots);
        for (int i = 0; i < exp_len; ++i)
            mask_long[position + i] = (long) 1;
        ZZX mask_zzx;
        comparator.m_context.getView().encode(mask_zzx, mask_long);

        double size = conv<double>(embeddingLargestCoeff(mask_zzx, comparator.m_context.getZMStar()));
        DoubleCRT mask_crt = DoubleCRT(mask_zzx, comparator.m_context, comparator.m_context.allPrimes());
        extractionMask.push_back(mask_crt);
        extractionMaskSize.push_back(size);
    }

    void SERVER::totalSums(Ctxt& ctxt, unsigned long max_per, unsigned long exp_len)
    {
        if (max_per == 1)
            return;

        Ctxt orig = ctxt;

        long k = NTL::NumBits(max_per);
        long e = exp_len;

        for (long i = k - 2; i >= 0; i--) {
            Ctxt tmp1 = ctxt;
            rotate(tmp1, e);
            ctxt += tmp1; // ctxt = ctxt + (ctxt >>> e)
            e = 2 * e;

            if (NTL::bit(max_per, i)) {
                Ctxt tmp2 = orig;
                rotate(tmp2, e);
                ctxt += tmp2; // ctxt = ctxt + (orig >>> e)
                                // NOTE: we could have also computed
                                // ctxt =  (ctxt >>> e) + orig, however,
                                // this would give us greater depth/noise
                e += exp_len;
            }
        }
    }

    void SERVER::testTS(Ctxt& ctxt)
    {
        totalSums(ctxt, max_packed, exp_len);
    }
					
	void SERVER::Query(HEQuery& q, Ctxt_mat& res)
	{
		res.resize(q.dest.size()); // resize result so we have #dest rows
		for (auto& row: res) row.reserve(Col);

		// Ctxt_mat less_mod_ctxt_arr, eq_mod_ctxt_arr;
		// less_mod_ctxt_arr.resize(Col);
		// eq_mod_ctxt_arr.resize(Col);
		// for (auto& row: less_mod_ctxt_arr) row.reserve(comparator.m_slotDeg);
		// for (auto& row: eq_mod_ctxt_arr) row.reserve(comparator.m_slotDeg);

		for (unsigned long i = 0; i < Col; ++i)
		{
			//UNI
			Ctxt z_ctxt = DB[q.source][i];
			z_ctxt -= q.query;
			vector<Ctxt> mod_p_coefs;
			comparator.extract_mod_p(mod_p_coefs, z_ctxt);
			
			// for(unsigned long iCoef = 0; iCoef < comparator.m_slotDeg; ++iCoef)
			// {
			// 	Ctxt ctxt_less = Ctxt(comparator.m_pk);
			// 	Ctxt ctxt_eq = Ctxt(comparator.m_pk);
			// 	comparator.evaluate_univar_less_poly(ctxt_less, ctxt_eq, mod_p_coefs[iCoef]);
			// 	less_mod_ctxt_arr[i].emplace_back(ctxt_less);
			// 	ctxt_eq.negate();
			// 	ctxt_eq.addConstant(ZZ(1));
			// 	eq_mod_ctxt_arr[i].emplace_back(ctxt_eq);
			// }
			// Ctxt ctxt_less = less_mod_ctxt_arr[i][comparator.m_slotDeg - 1];
			// Ctxt ctxt_eq = eq_mod_ctxt_arr[i][comparator.m_slotDeg - 1];
			// for(long iCoef = comparator.m_slotDeg - 2; iCoef >= 0; iCoef--)
			// {
			// 	Ctxt tmp = ctxt_eq;
			// 	tmp *= less_mod_ctxt_arr[i][iCoef];
			// 	ctxt_less += tmp;

			// 	ctxt_eq *= eq_mod_ctxt_arr[i][iCoef];
			// }
            Ctxt ctxt_less = Ctxt(comparator.m_pk);
            Ctxt ctxt_eq = Ctxt(comparator.m_pk);
            for (long iCoef = D - 1; iCoef >= 0; --iCoef)
            {
                Ctxt tmp_less = Ctxt(comparator.m_pk);
                Ctxt tmp_eq = Ctxt(comparator.m_pk);
                comparator.evaluate_univar_less_poly(tmp_less, tmp_eq, mod_p_coefs[iCoef]);
                tmp_eq.negate();
                tmp_eq.addConstant(ZZ(1));
                if (iCoef == D - 1) 
                {
                    ctxt_less = tmp_less;
                    ctxt_eq = tmp_eq;
                }
                else
                {
                    Ctxt tmp = ctxt_eq;
                    tmp *= tmp_less;
                    ctxt_less += tmp;

                    ctxt_eq *= tmp_eq;
                }
            }
			Ctxt eq_final = ctxt_eq;
            long sft = 1;
            while (sft < comparator.m_expansionLen)
			{
				Ctxt pos_shift = eq_final;
				comparator.batch_shift_for_mul(pos_shift, 0, sft);
				eq_final *= pos_shift;
				Ctxt neg_shift = eq_final;
				comparator.batch_shift_for_mul(neg_shift, 0, -sft);
				eq_final *= neg_shift;
				sft <<= 1;
			}

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
        
        Ctxt_vec q_mod_p;
        comparator.extract_mod_p(q_mod_p, q.query);

        Ctxt_vec extracted_UIDs;
        long sft = 1;
        for (unsigned long i = 0; i < Y; ++i) {
            // cout << "extract UID" << endl;
            Ctxt k_ctxt = Index.keys()[i];
            sft = 1;
            // Ctxt_vec ctxt_eq_p;
            Ctxt_vec k_mod_p;
            comparator.extract_mod_p(k_mod_p, k_ctxt);

            Ctxt ctxt_eq(comparator.m_pk);
            // for (long iCoef = 0; iCoef < D; iCoef++)
            for (long iCoef = D-1; iCoef >= 0; iCoef--)
            {
                // cout << "iCoef: " << iCoef << endl;
                Ctxt eql = q_mod_p[iCoef];
                eql -= k_mod_p[iCoef];
                //equality circuit
                comparator.mapTo01_subfield(eql, 1);
                eql.negate();
                eql.addConstant(ZZ(1));
                // ctxt_eq_p.push_back(eql);
                if (iCoef == D-1) ctxt_eq = eql;
                else ctxt_eq *= eql;
            }
            // Ctxt ctxt_eq = ctxt_eq_p[D-1];
            // for(long iCoef = D - 2; iCoef >= 0; iCoef--)
            //     ctxt_eq *= ctxt_eq_p[iCoef];

            if (exp_len != 1)
            {
                while (sft < exp_len)
                {
                    // cout << "sft: " << sft << endl;
                    Ctxt pos_shift = ctxt_eq;
                    comparator.batch_shift_for_mul(pos_shift, 0, sft);
                    ctxt_eq *= pos_shift;
                    Ctxt neg_shift = ctxt_eq;
                    comparator.batch_shift_for_mul(neg_shift, 0, -sft);
                    ctxt_eq *= neg_shift;
                    sft <<= 1;
                }
            }
            Ctxt UID_extract = Index.uids()[0][i];
            UID_extract *= ctxt_eq;
            for (int j = 1; j < X; ++j)
            {
                Ctxt uid = Index.uids()[j][i];
                uid *= ctxt_eq;
                rotate(UID_extract, -exp_len);
                // rotate(uid, -exp_len * j);
                UID_extract += uid;
            }
            extracted_UIDs.push_back(UID_extract);
        }
        
        for (auto& ctxt: extracted_UIDs)
        {
            cout << "For each ciphertext..." << endl;
            Ctxt_vec final_res;
            for (int i = 0; i < max_packed; ++i) 
            {
                HELIB_NTIMER_START(nslot);
                Ctxt extract = ctxt;
                extract.multByConstant(extractionMask[i], extractionMaskSize[i]); // extract UID
                //replicate 1
                // Ctxt TS_1 = extract;
                // for (int j = 1; j < max_packed; ++j)
                // {
                //     rotate(extract, -exp_len);
                //     TS_1 += extract;
                // }
                //replicate 1 end
                totalSums(extract, max_packed, exp_len);

                //EQ with UID in DB
                // Ctxt EQ_Extract;
                Ctxt_vec DEST_Extract;
                DEST_Extract.reserve(q.dest.size());
                Ctxt_vec ext_p;
                comparator.extract_mod_p(ext_p, extract);
                for (int j = 0; j < DB[0].size(); ++j)
                { //for each ctxt in a row,
                    sft = 1;
                    Ctxt_vec c_uid_p;
                    // Ctxt_vec ctxt_eq_p;

                    comparator.extract_mod_p(c_uid_p, DB[0][j]);

                    //process first one
                    Ctxt ctxt_eq(comparator.m_pk);
                    // for (long iCoef = 0; iCoef < D; iCoef++)
                    for (long iCoef = D-1; iCoef >= 0; iCoef--)
                    {
                        Ctxt eql = ext_p[iCoef];
                        eql -= c_uid_p[iCoef];
                        //equality circuit
                        comparator.mapTo01_subfield(eql, 1);
                        
                        eql.negate();
                        eql.addConstant(ZZ(1));
                        if (iCoef == D-1) ctxt_eq = eql;
                        else ctxt_eq *= eql;
                    }
                    // Ctxt ctxt_eq = ctxt_eq_p[D-1];
                    // for (long iCoef = D - 2; iCoef >= 0; iCoef--)
                    //     ctxt_eq *= ctxt_eq_p[iCoef];
                    while (sft < exp_len)
                    {
                        Ctxt pos_shift = ctxt_eq;
                        comparator.batch_shift_for_mul(pos_shift, 0, sft);
                        ctxt_eq *= pos_shift;
                        Ctxt neg_shift = ctxt_eq;
                        comparator.batch_shift_for_mul(neg_shift, 0, -sft);
                        ctxt_eq *= neg_shift;
                        sft <<= 1;
                    }
                    for (int k = 0; k < q.dest.size(); ++k)
                    {
                        Ctxt tmp = ctxt_eq;
                        tmp *= DB[q.dest[k]][j];
                        if (!j)
                            DEST_Extract.push_back(tmp);
                        else
                            DEST_Extract[k] += tmp;
                    }
                }

                for (int k = 0; k < q.dest.size(); ++k)
                {
                    totalSums(DEST_Extract[k], max_packed, exp_len);
                    DEST_Extract[k].multByConstant(extractionMask[i], extractionMaskSize[i]);
                }

                if (!i) //if first
                    final_res = DEST_Extract;
                else
                    for (int k = 0; k < q.dest.size(); ++k) final_res[k] += DEST_Extract[k];
                cout << "  capacity: " << final_res[0].bitCapacity() << ", iscorrect: " << final_res[0].isCorrect() << endl;
                HELIB_NTIMER_STOP(nslot);
                helib::printNamedTimer(cout, "nslot");
            }
            // helib::printNamedTimer(cout, "nslot");
            

            for (int k = 0; k < q.dest.size(); ++k) res[k].push_back(final_res[k]);
        }
    }
} 

