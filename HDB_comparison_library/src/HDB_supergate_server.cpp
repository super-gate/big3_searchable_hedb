#include <stdio.h>
#include <iostream>

#include <helib/debugging.h>
#include "HDB_supergate_server.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

using namespace HDB_supergate_;
using namespace helib;
using namespace std;
using namespace he_cmp;
using namespace NTL;

namespace HDB_supergate_server_{
    /* @deprecated Construction used only for simulation */
    // SERVER::SERVER (Comparator& comparator,
	// 				Ctxt_mat& db,
	// 				CtxtIndexFile& indFile,
	// 				bool v) : comparator(comparator), 
	// 						  DB(db), 
	// 						  IndexFile(indFile),
	// 						  Row(db.size()),
	// 						  Col(db[0].size()),
	// 						  verbose(v),
    //                           nslots(Comp->m_context.getNSlots()),
    //                           exp_len(exp_len),
    //                           max_packed(nslots / exp_len),
    //                           D(Comp->m_slotDeg)
    // {
    //     create_all_extraction_masks();
    // };

    /* Constructor */
    SERVER::SERVER(bool v) : verbose(v) {};

    void SERVER::create_all_extraction_masks() {
        for (unsigned long i = 0; i < max_packed; ++i)
            create_extraction_mask(i * exp_len);
    }

    void SERVER::create_extraction_mask(int position)
    {
        // only works if contx contains value
        vector<long> mask_long(nslots);
        for (unsigned long i = 0; i < exp_len; ++i)
            mask_long[position + i] = (long) 1;
        ZZX mask_zzx;
        Contx->getView().encode(mask_zzx, mask_long);

        double size = conv<double>(embeddingLargestCoeff(mask_zzx, Contx->getZMStar()));
        DoubleCRT mask_crt = DoubleCRT(mask_zzx, *Contx, Contx->allPrimes());
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
    
    void SERVER::constructDBPath(string db_name, BGV_param param, string& db_path)
    {
        stringstream full_path;
        full_path << "./HEDB/" 
                  << param.p << "_" << param.m << "_" << param.nb_primes << "_" << param.c << "_" << param.r << "_" << param.scale << "_" << param.d << "_" << param.expansion_len << "/"
                  << db_name;
        db_path = full_path.str();
    }

    void SERVER::SaveDB(string db_name, BGV_param param, Context& contx, PubKey& pk, Ctxt_mat& db, optional<CtxtIndexFile>& indFile)
    {
        if (verbose) cout << "Saving into HEDB..." << endl;
        string db_path;
        constructDBPath(db_name, param, db_path);
        fs::create_directories(db_path);

        string context_filename = db_path + "/context";
        serialize_to_file(context_filename, contx);

        string  pubkey_filename = db_path + "/pubkey";
        serialize_to_file(pubkey_filename, pk);

        ofstream outDBFile;
        outDBFile.open(db_path + "/db", ios::out);
        if (outDBFile.is_open()) {
            // Write the context to a file
            write_raw_ctxt_mat(outDBFile, db);
            // Close the ofstream
            outDBFile.close();
        } else {
            throw std::runtime_error("Could not open file 'db'.");
        }
        // cout << "db done" << endl;

        if (indFile)
        {
            ofstream outIndFile;
            outIndFile.open(db_path + "/indFile", ios::out);
            if (outIndFile.is_open())
            {
                indFile.value().write_raw_index_file(outIndFile);
                outIndFile.close();
            } else {
                throw std::runtime_error("Could not open file 'indFile'.");
            }
        }
        if (verbose) cout << "Done! DB is saved safely" << endl;
    }

    int8_t SERVER::loadContext(string db_path)
    {
        if (verbose) cout << "Loading Context...\n";
        ifstream inContextFile;
        string context_filename = db_path + "/context";
        inContextFile.open(context_filename);
        if (!inContextFile.is_open()) {
            cerr << "Could not open file 'context'." << endl;
            return -1;
        }
        Context* contx = Context::readPtrFrom(inContextFile);
        inContextFile.close();
        Contx.reset(contx);
        return 0;
    }

    int8_t SERVER::loadPubKey(string db_path)
    {
        if (verbose) cout << "Loading Public Key...\n";
        ifstream inPubKeyFile;
        string pubkey_filename = db_path + "/pubkey";
        inPubKeyFile.open(pubkey_filename);
        if (!inPubKeyFile.is_open()) {
            cerr << "Could not open file 'pubkey'." << endl;
            return -1;
        }
        PubKey pk = PubKey::readFrom(inPubKeyFile, *Contx);
        inPubKeyFile.close();
        PublicKey = make_unique<PubKey>(pk);
        return 0;
    }

    int8_t SERVER::loadComparator(BGV_param param)
    {
        if (verbose) cout << "Loading Comparator ...\n";
        Comparator* newComp = new Comparator(*Contx, UNI, param.d, param.expansion_len, *PublicKey, verbose);
        Comp.reset(newComp);
        return 0;
    }

    int8_t SERVER::loadDB(string db_path)
    {
        if (verbose) cout << "Loading DB...\n";
        ifstream inDBFile;
        string db_filename = db_path + "/db";
        inDBFile.open(db_filename);
        Ctxt_mat db;
        if (inDBFile.is_open()) {
            // Read in the context from the file
            read_raw_ctxt_mat(inDBFile, db, *PublicKey);
            // Close the ifstream
            inDBFile.close();
        } else {
            cerr << "Could not open file 'db'." << endl;
            return -1;
        }
        Database = make_unique<Ctxt_mat>(db);
        return 0;
    }
    
    int8_t SERVER::loadIndexFile(string db_path)
    {
        if (verbose) cout << "Loading Index File...\n";
        ifstream inIndexFile;
        string ind_filename = db_path + "/indFile";
        inIndexFile.open(ind_filename);
        CtxtIndexFile indFile;
        if (inIndexFile.is_open()) {
            // Read in the context from the file
            indFile.read_raw_index_file(inIndexFile, *PublicKey);
            // Close the ifstream
            inIndexFile.close();
        } else {
            cerr << "Could not find or open file 'indFile'." << endl;
            return -1;
        }
        IndexFile = make_unique<CtxtIndexFile>(indFile);
        return 0;
    }

    void SERVER::loadRest(string db_name, BGV_param param)
    {
        Row = (*Database).size();
        Col = (*Database)[0].size();
        nslots = Contx->getNSlots();
        exp_len = Comp->m_expansionLen;
        max_packed = nslots / exp_len;
        D = Comp->m_slotDeg;
        create_all_extraction_masks();
    }

    int8_t SERVER::LoadData(string db_name, BGV_param param, bool index)
    {
        string db_path;
        constructDBPath(db_name, param, db_path);
        if (!fs::exists(db_path))
        {
            cerr << "Path: " << db_path << " does not exist." << endl;
            return -1;
        }
        if (verbose) cout << "Loading All Data..." << endl;

        if (loadContext(db_path) == -1) return -1;
        if (loadPubKey(db_path) == -1) return -1;
        if (loadComparator(param) == -1) return -1;
        if (loadDB(db_path) == -1) return -1;
        if (index && loadIndexFile(db_path) == -1) return -1;
        loadRest(db_path, param);
        if (verbose) cout << "Data all loaded!" << endl;

        return 0;
    }

    HEQuery* SERVER::deserializeQuery(istream& is)
    {
        HEQuery* query = new HEQuery(*PublicKey);
        query->read(is);
        return query;
    }

    void SERVER::ClearData()
    {
        Comp.reset(nullptr);
        Contx.reset(nullptr);
        PublicKey.reset(nullptr);
        Database.reset(nullptr);
        IndexFile.reset(nullptr);
        Row = 0;
        Col = 0;
        extractionMask.clear();
        extractionMaskSize.clear();
        nslots = 0;
        exp_len = 0;
        max_packed = 0;
        D = 0;
    }

    int8_t SERVER::ProcessQuery(string db_name, BGV_param param, Q_MODE mode, istream& qStream, Ctxt_mat& result)
    {
        if (LoadData(db_name, param, mode == IND) == -1) return -1;
        if (verbose) cout << "Querying..." << endl;
        HEQuery query = *(deserializeQuery(qStream));
        cout << query.dest.size() << endl;
        switch(mode)
        {
            case NORMAL:
                Query(query, result);
                break;
            case EXTF:
                QueryExtensionField(query, result);
                break;
            case IND:
                QueryWithIndex(query, result);
                break;
            default:
                break;
        }
        ClearData();
        return 0;
    }

    // int8_t SERVER::LoadAndProcessQuery(string db_name, BGV_param param, Q_MODE mode, istream& qStream, Ctxt_mat& result)
    // {
    //     if (LoadData(db_name, param, mode == IND) == -1) return -1;
    //     if (verbose) cout << "Querying..." << endl;
    //     HEQuery query = *(deserializeQuery(qStream));
    //     cout << query.dest.size() << endl;
    //     switch(mode)
    //     {
    //         case NORMAL:
    //             Query(query, result);
    //             break;
    //         case EXTF:
    //             QueryExtensionField(query, result);
    //             break;
    //         case IND:
    //             QueryWithIndex(query, result);
    //             break;
    //         default:
    //             break;
    //     }
    //     // ClearData();
    //     return 0;
    // }
					
	void SERVER::Query(HEQuery& q, Ctxt_mat& res)
	{
		res.resize(q.dest.size()); // resize result so we have #dest rows
		for (auto& row: res) row.reserve(Col);


		for (unsigned long i = 0; i < Col; ++i)
		{
			//UNI
			Ctxt z_ctxt = (*Database)[q.source][i];
			z_ctxt -= q.query;
			vector<Ctxt> mod_p_coefs;
			Comp->extract_mod_p(mod_p_coefs, z_ctxt);
			
            Ctxt ctxt_less = Ctxt(*PublicKey);
            Ctxt ctxt_eq = Ctxt(*PublicKey);
            for (long iCoef = D - 1; iCoef >= 0; --iCoef)
            {
                Ctxt tmp_less = Ctxt(*PublicKey);
                Ctxt tmp_eq = Ctxt(*PublicKey);
                Comp->evaluate_univar_less_poly(tmp_less, tmp_eq, mod_p_coefs[iCoef]);
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
            Ctxt less_final = ctxt_less;
			if(exp_len != 1)
			{
				Comp->shift_and_mul(ctxt_eq, 0);
				Comp->batch_shift_for_mul(ctxt_eq, 0, -1);

				// ctxt_less *= ctxt_eq;
                less_final = ctxt_eq;
                less_final.multiplyBy(ctxt_less);
				Comp->shift_and_add(less_final, 0);
			}
            unsigned long sft = 1;
            while (sft < exp_len)
			{
				Ctxt eq_pos_shift = eq_final;
				Comp->batch_shift_for_mul(eq_pos_shift, 0, sft);
				eq_final *= eq_pos_shift;
				Ctxt eq_neg_shift = eq_final;
				Comp->batch_shift_for_mul(eq_neg_shift, 0, -sft);
				eq_final *= eq_neg_shift;
                
                Ctxt less_pos_shift = less_final;
				Comp->batch_shift(less_pos_shift, 0, sft);
				less_final += less_pos_shift;
				sft <<= 1;
			}
			
			eq_final *= q.Q_type.first;
			less_final *= q.Q_type.second;

			Ctxt query_final = eq_final;
			query_final += less_final;

			for (unsigned long j = 0; j < q.dest.size(); ++j)
			{
                // Ctxt res_final = less_final;
				Ctxt res_final = query_final;
				res_final *= (*Database)[q.dest[j]][i];
				res[j].emplace_back(res_final);
			}
		}
	}

    void SERVER::QueryExtensionField(HEQuery& q, Ctxt_mat& res)
	{
		res.resize(q.dest.size()); // resize result so we have #dest rows
        unsigned long ordP = Comp->m_context.getOrdP();
        unsigned long maxPerSlot = floor(float(ordP) / D);
        cout << "ordP: " << ordP << ", D: " << D << endl;
        unsigned long reducedCol = ceil(float(Col) / maxPerSlot);
        cout << "mperslot: " << maxPerSlot << " reduced: " << reducedCol << endl;
        for (auto& row: res)
            for (uint i = 0; i < reducedCol; ++i) row.emplace_back(*PublicKey);
		
        vector<PtxtArray> mask(maxPerSlot, PtxtArray(Comp->m_context));
        for (uint i = 0; i < mask.size(); ++i)
        {
            ZZX msk(INIT_MONO, D*i, 1);
            mask[i].load(msk);
        }
        // for (auto& m: mask) cout << m << endl;

		for (unsigned long i = 0; i < Col; ++i)
		{
            HELIB_NTIMER_START(timer_ForEachCol);
			//UNI
			Ctxt z_ctxt = (*Database)[q.source][i];
			z_ctxt -= q.query;
			vector<Ctxt> mod_p_coefs;
			Comp->extract_mod_p(mod_p_coefs, z_ctxt);
			
            Ctxt ctxt_less = Ctxt(*PublicKey);
            Ctxt ctxt_eq = Ctxt(*PublicKey);
            for (long iCoef = D - 1; iCoef >= 0; --iCoef)
            {
                Ctxt tmp_less = Ctxt(*PublicKey);
                Ctxt tmp_eq = Ctxt(*PublicKey);
                Comp->evaluate_univar_less_poly(tmp_less, tmp_eq, mod_p_coefs[iCoef]);
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
            unsigned long sft = 1;
            // while (sft < exp_len)
			// {
			// 	Ctxt pos_shift = eq_final;
			// 	Comp->batch_shift_for_mul(pos_shift, 0, sft);
			// 	eq_final *= pos_shift;
			// 	Ctxt neg_shift = eq_final;
			// 	Comp->batch_shift_for_mul(neg_shift, 0, -sft);
			// 	eq_final *= neg_shift;
			// 	sft <<= 1;
			// }

			if(exp_len != 1)
			{
				Comp->shift_and_mul(ctxt_eq, 0);
				Comp->batch_shift_for_mul(ctxt_eq, 0, -1);

				ctxt_less *= ctxt_eq;
				Comp->shift_and_add(ctxt_less, 0);
			}
			Ctxt less_final = ctxt_less;
            // Ctxt less_final = Ctxt(*PublicKey);
            // Comp->compare(less_final, (*Database)[q.source][i], q.query);
            sft = 1;
            while (sft < exp_len)
			{
				Ctxt pos_shift = less_final;
				Comp->batch_shift(pos_shift, 0, sft);
				less_final += pos_shift;
				sft <<= 1;
			}

			eq_final *= q.Q_type.first;
			less_final *= q.Q_type.second;

			Ctxt query_final = eq_final;
			query_final += less_final;
            // cout << "Capacity: " << query_final.bitCapacity() << " OK: " << query_final.isCorrect() << endl;

            int ind = i / maxPerSlot;
            unsigned long k = i % maxPerSlot;
			for (unsigned long j = 0; j < q.dest.size(); ++j)
			{
                Ctxt res_final = query_final;
                res_final *= (*Database)[q.dest[j]][i];
                res_final *= mask[k];
				
				res[j][ind] += res_final;
			}
            HELIB_NTIMER_STOP(timer_ForEachCol);
		}
        printNamedTimer(cout, "timer_ForEachCol");
	}

	//can only do EQ query right now
	void SERVER::QueryWithIndex(HEQuery& q, Ctxt_mat& res)
	{
		CtxtIndex& Index = IndexFile->find(q.source);
        unsigned long X = Index.getX();
        unsigned long Y = Index.getY();

        res.resize(q.dest.size()); // resize result so we have #dest rows
        for (auto& row: res) row.reserve(Y);
        
        Ctxt_vec q_mod_p;
        Comp->extract_mod_p(q_mod_p, q.query);

        Ctxt_vec extracted_UIDs;
        unsigned long sft = 1;
        for (unsigned long i = 0; i < Y; ++i) {
            // cout << "extract UID" << endl;
            Ctxt k_ctxt = Index.keys()[i];
            sft = 1;
            // Ctxt_vec ctxt_eq_p;
            Ctxt_vec k_mod_p;
            Comp->extract_mod_p(k_mod_p, k_ctxt);

            Ctxt ctxt_eq(*PublicKey);
            // for (long iCoef = 0; iCoef < D; iCoef++)
            for (long iCoef = D-1; iCoef >= 0; iCoef--)
            {
                // cout << "iCoef: " << iCoef << endl;
                Ctxt eql = q_mod_p[iCoef];
                eql -= k_mod_p[iCoef];
                //equality circuit
                Comp->mapTo01_subfield(eql, 1);
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
                    Comp->batch_shift_for_mul(pos_shift, 0, sft);
                    ctxt_eq *= pos_shift;
                    Ctxt neg_shift = ctxt_eq;
                    Comp->batch_shift_for_mul(neg_shift, 0, -sft);
                    ctxt_eq *= neg_shift;
                    sft <<= 1;
                }
            }
            Ctxt UID_extract = Index.uids()[0][i];
            UID_extract *= ctxt_eq;
            for (uint j = 1; j < X; ++j)
            {
                Ctxt uid = Index.uids()[j][i];
                uid *= ctxt_eq;
                rotate(UID_extract, -exp_len);
                // rotate(uid, -exp_len * j);
                UID_extract += uid;
            }
            extracted_UIDs.push_back(UID_extract);
        }
        
        // cout << "number of ciphertexts: " << extracted_UIDs.size() << endl;
        for (auto& ctxt: extracted_UIDs)
        {
            // cout << "For each ciphertext..." << endl;
            Ctxt_vec final_res;
            for (uint i = 0; i < max_packed; ++i) 
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
                Comp->extract_mod_p(ext_p, extract);
                for (uint j = 0; j < (*Database)[0].size(); ++j)
                { //for each ctxt in a row,
                    sft = 1;
                    Ctxt_vec c_uid_p;
                    // Ctxt_vec ctxt_eq_p;

                    Comp->extract_mod_p(c_uid_p, (*Database)[0][j]);

                    //process first one
                    Ctxt ctxt_eq(*PublicKey);
                    // for (long iCoef = 0; iCoef < D; iCoef++)
                    for (long iCoef = D-1; iCoef >= 0; iCoef--)
                    {
                        Ctxt eql = ext_p[iCoef];
                        eql -= c_uid_p[iCoef];
                        //equality circuit
                        Comp->mapTo01_subfield(eql, 1);
                        
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
                        Comp->batch_shift_for_mul(pos_shift, 0, sft);
                        ctxt_eq *= pos_shift;
                        Ctxt neg_shift = ctxt_eq;
                        Comp->batch_shift_for_mul(neg_shift, 0, -sft);
                        ctxt_eq *= neg_shift;
                        sft <<= 1;
                    }
                    for (uint k = 0; k < q.dest.size(); ++k)
                    {
                        Ctxt tmp = ctxt_eq;
                        tmp *= (*Database)[q.dest[k]][j];
                        if (!j)
                            DEST_Extract.push_back(tmp);
                        else
                            DEST_Extract[k] += tmp;
                    }
                }

                for (uint k = 0; k < q.dest.size(); ++k)
                {
                    totalSums(DEST_Extract[k], max_packed, exp_len);
                    DEST_Extract[k].multByConstant(extractionMask[i], extractionMaskSize[i]);
                }

                if (!i) //if first
                    final_res = DEST_Extract;
                else
                    for (uint k = 0; k < q.dest.size(); ++k) final_res[k] += DEST_Extract[k];
                // cout << "  capacity: " << final_res[0].bitCapacity() << ", iscorrect: " << final_res[0].isCorrect() << endl;
                HELIB_NTIMER_STOP(nslot);
                // helib::printNamedTimer(cout, "nslot");
            }
            // helib::printNamedTimer(cout, "nslot");
            

            for (uint k = 0; k < q.dest.size(); ++k) res[k].push_back(final_res[k]);
        }
    }
} 

