#include<iostream>
#include <string_view>

#include <helib/debugging.h>
#include <NTL/mat_ZZ.h>
#include <NTL/ZZX.h>
#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "HDB_supergate_user.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include <time.h>

using namespace NTL;
using namespace std;
using namespace he_cmp;
using namespace HDB_supergate_;
using namespace helib;

namespace HDB_supergate_user_{
    /* Construction */
    USER::USER(Comparator& comparator, const Context& contx, PubKey& pk, SecKey& sk, bool v) : comparator(comparator), contx(contx), pk(pk), sk(sk), verbose(v) {};

	unsigned long USER::max(){
		return input_range;
	};

	void USER::printDecrypted(Ctxt& ctxt)
    {
        vector<ZZX> decrypted_cipher(nslots);
        contx.getView().decrypt(ctxt, sk, decrypted_cipher);

        for(unsigned long i=0; i < nslots; i++)
        {
            printZZX(cout, decrypted_cipher[i], ord_p);
            cout << ", ";
        }
        cout<<endl;
    };

	void USER::printCtxtMat(Ctxt_mat& db)
	{
		for (auto& row: db)
		{
			cout << "Row" << endl;
			for (auto& elem: row)
			{
				printDecrypted(elem);
				cout << "________________________________________________________" << endl;
			}
		}
	}

    void USER::ShowRes(std::vector<ZZX> datas, Ctxt_vec &less_vector, Ctxt_vec &equal_vector, Ctxt_mat &equal_result, Ctxt_mat &less_result, unsigned long Row, unsigned long num_db_category, unsigned long num_db_element, Q_TYPE_t type)  
	{
		unsigned long cipher_num = Row/max_packed;

		// clock_t start, end;
	//	double result;

		// start = clock();
		//equal vector decrypt
		vector<vector<ZZX>> dec_equal_vec;
		dec_equal_vec.resize(cipher_num);
		//cout<<"cipher_num: "<<cipher_num<<endl;


		for (unsigned long i=0; i<cipher_num ; i++)
		{
			//cout<<"equal ciphertext"<<endl;
			//cout<< equal_vector[i]<<" "<<endl;
			ea.decrypt(equal_vector[i], sk, dec_equal_vec[i]);
		}

		//cout<<endl;
		//cout<<endl;

		//less vector decrypt
		vector<vector<ZZX>> dec_less_vec;
		dec_less_vec.resize(cipher_num);
		for(unsigned long i=0; i<cipher_num ; i++)
		{
			//cout<<"less ciphertext"<<endl;
			//cout<< less_vector <<" ";
			ea.decrypt(less_vector[i], sk, dec_less_vec[i]);
		}

		//cout<<endl;
		//cout<<endl;
		//equal result
		vector<vector<vector<ZZX>>> dec_eq_result;
		
		dec_eq_result.resize(num_db_category);

		//cout<<"equal result ciphertext" <<endl;
		for(unsigned long i=0; i< num_db_category; i++)
		{
			dec_eq_result[i].resize(cipher_num);
			for(unsigned long j = 0; j<cipher_num; j++)
			{	
				//cout<< equal_result[i][j]<<" ";
				ea.decrypt(equal_result[i][j], sk, dec_eq_result[i][j]);
			}
			//cout<<endl;
		}
		//cout<<endl;

		//less result
	//	cout<<"less result ciphertext" <<endl;
		vector<vector<vector<ZZX>>> dec_less_result;

		dec_less_result.resize(num_db_category);

		for(unsigned long i = 0; i<num_db_category; i++)
		{	
			dec_less_result[i].resize(cipher_num);
			for(unsigned long j = 0; j<cipher_num; j++)
			{	
				//cout<<less_result[i][j]<<" ";
				ea.decrypt(less_result[i][j], sk, dec_less_result[i][j]);
			}
			//cout<<endl;
		}

		ZZX *zero = new ZZX(0);
		ZZX *one = new ZZX(1);

		//less final vec and final result

		for(unsigned long i=0; i<cipher_num; i++)
        {   
            for(unsigned long j=0; j< max_packed; j++)
            {   
                for(unsigned long k=0; k< comparator.m_expansionLen; k++)
                {   
                    if(dec_less_vec[i][j*comparator.m_expansionLen + k] == *zero && dec_equal_vec[i][j*comparator.m_expansionLen + k] == *one)
                    {   
						
                        dec_less_vec[i][j*comparator.m_expansionLen + k] = dec_equal_vec[i][j*comparator.m_expansionLen + k];

						for(unsigned long l=0; l<num_db_category; l++)
						{
							dec_less_result[l][i][j*comparator.m_expansionLen + k] = dec_eq_result[l][i][j*comparator.m_expansionLen + k];
						}
                    }
                }
            }
        }


		//equal final result
		for(unsigned long i=0; i<cipher_num; i++)
		{

			for(unsigned long j=0; j<max_packed; j++)
			{
				int eq = 1;
				for(unsigned long k = 0; k<comparator.m_expansionLen-1;k++)
				{
					if(dec_equal_vec[i][j*comparator.m_expansionLen + k] != dec_equal_vec[i][j*comparator.m_expansionLen + k+1])
					{
						eq = 0;
					}
				}

				if(eq==0)
				{
					for(unsigned long k=0; k<comparator.m_expansionLen; k++)
					{	
						dec_equal_vec[i][j*comparator.m_expansionLen + k] = 0;
						for(unsigned long l= 0; l<num_db_category; l++)
						{
							dec_eq_result[l][i][j*comparator.m_expansionLen+k] = 0;
						}
					}
				}
			}
		}

		//less final result

		for(unsigned long i = 0; i<cipher_num; i++)
		{
			for(unsigned long j=0; j<nslots; j++)
			{
				if(dec_less_vec[i][j] == dec_equal_vec[i][j])
				{
					dec_less_vec[i][j] = 0;
					for(unsigned long k=0; k< num_db_category; k++)
					{
						dec_less_result[k][i][j] = 0;
					}
				}
			}
		}
		
		for(unsigned long i=0; i<cipher_num; i++)
		{
			for(unsigned long j=0; j<max_packed; j++)
			{
				int eq = 1;
				for(unsigned long k=0; k<comparator.m_expansionLen-1; k++)
				{
					if(dec_less_vec[i][j*comparator.m_expansionLen + k] != dec_less_vec[i][j*comparator.m_expansionLen + k+1])
					{	
						eq = 0;
					}
				}

				if(eq==0)
				{
					for(unsigned long k=0;k<comparator.m_expansionLen;k++)
					{
						dec_less_vec[i][j*comparator.m_expansionLen+k] = 0;
						for(unsigned long l= 0; l< num_db_category;l++)
						{
							dec_less_result[l][i][j*comparator.m_expansionLen+k] =0;
						}
					}
				}
			}
		}

	//	end = clock();
	//	result = (double) end - start;
	//	cout<<"time: "<<result<<"ms"<<endl;
		//print equal vector

	//	cout<<endl;
		unsigned long num = 0;
		long data;
		long coef;

		if(type == EQ)
		{
			cout<<"equal vector" <<endl;
			unsigned long num = 0;
			for(unsigned long i=0; i<cipher_num; i++)
			{
			    for(unsigned long j=0; j<max_packed*comparator.m_expansionLen; j++)//deleted remaining slots in a ciphertext
			    {	
					num += 1;
			        printZZX(cout, dec_equal_vec[i][j], ord_p);
					cout<<" ";
					if(num == num_db_element * comparator.m_expansionLen)//delete remaining ciphertext
			        {
			            break;
			        }
	            }
	        }
	        cout<<endl;
		
			//print equal result

			cout<<"equal result"<<endl;
			for(unsigned long i=0; i<num_db_category; i++)//print all columns
			{
				num = 0;
				for(unsigned long j=0; j<cipher_num; j++)
				{
					for(unsigned long k=0; k<max_packed*comparator.m_expansionLen; k++)
					{
						printZZX(cout, dec_eq_result[i][j][k], ord_p);
						cout<<" ";
						num += 1;
						if(num == num_db_element * comparator.m_expansionLen)
		                {
			                break;
				        }
	
					}
				}
				cout<<endl;
			}
			cout<<endl;
		
		//long data;
		//long coef;

			std::vector<std::vector<long>> data_orig;

			data_orig.resize(num_db_element);
			for(unsigned long i=0; i< num_db_element;i++)
			{
				data_orig[i].resize(num_db_category);
			}

			for(unsigned long i=0; i<num_db_category; i++)
			{		
				num = 0;
				for(unsigned long j=0; j<cipher_num; j++)
				{
					for(unsigned long k=0; k< max_packed; k++)
					{
						data = 0;
						for(unsigned long l=0; l<comparator.m_expansionLen; l++)
						{
							coef = 0;
							for(long degr = 0; degr< deg(dec_eq_result[i][j][k*comparator.m_expansionLen + l]) + 1; degr++)
							{
								coef += conv<long>(dec_eq_result[i][j][k*comparator.m_expansionLen + l][degr]) * pow(enc_base, degr);
							}
							data += conv<long>(coef) * pow(digit_base, l);
						}
						//cout<<"["<<data<<"] ";
						data_orig[j*max_packed + k][i] = data;
						num += 1;
						if(num == num_db_element)
						{
							break;
						}
					}
	
				}
				//cout<<endl;
			}
			//cout<<endl;
			
			for(unsigned long i = 0; i<num_db_element; i++)
			{
				for(unsigned long j = 0; j< num_db_category + 1;j++)
				{
					if(j == 0)
					{
						cout<<datas[i];
					}
					else
					{
						cout<<"["<<data_orig[i][j-1]<<"]";
					}
				}
				cout<<endl;
			}
			//return dec_equal_vec;
		}

		//print less vector

		if(type == LT)
		{
			cout<<"less vector" <<endl;
			num = 0;
			for(unsigned long i=0; i<cipher_num; i++)
			{
				for(unsigned long j=0; j<max_packed*comparator.m_expansionLen; j++)
				{
					printZZX(cout, dec_less_vec[i][j], ord_p);
					cout<<" ";
					num += 1;
					if(num == num_db_element * comparator.m_expansionLen)
					{
						break;
					}
				}
			}
			cout<<endl;
	
			//print less result
	
			cout<<"less result"<<endl;
			num = 0;
			for(unsigned long i=0; i<num_db_category; i++)
	        {
				num = 0;
	            for(unsigned long j=0; j<cipher_num; j++)
	            {
	                for(unsigned long k=0; k<max_packed*comparator.m_expansionLen; k++)
	                {
	                    printZZX(cout, dec_less_result[i][j][k], ord_p);
	                    cout<<" ";
						num += 1;
						if(num == num_db_element * comparator.m_expansionLen)
					    {
						    break;
					    }
	
	                }
	            }
	            cout<<endl;
	        }
			cout<<endl;
	
			std::vector<std::vector<long>> data_orig;

			data_orig.resize(num_db_element);
			for(unsigned long i=0; i< num_db_element;i++)
			{
				data_orig[i].resize(num_db_category);
			}

			//extended finite field -> number
			for(unsigned long i=0; i<num_db_category; i++)
			{
	
				num = 0;
				for(unsigned long j=0; j<cipher_num; j++)
				{
					for(unsigned long k=0; k< max_packed; k++)
					{
						data = 0;
						for(unsigned long l=0; l<comparator.m_expansionLen; l++)
						{
							coef = 0;
							for(long degr = 0; degr< deg(dec_less_result[i][j][k*comparator.m_expansionLen + l]) + 1; degr++)
							{
								coef += conv<long>(dec_less_result[i][j][k*comparator.m_expansionLen + l][degr]) * pow(enc_base, degr);
							}
							data += conv<long>(coef) * pow(digit_base, l);
						}
						//cout<<"["<<data<<"] ";
						data_orig[j*max_packed + k][i] = data;
						num += 1;
						if(num == num_db_element)
						{
							break;
						}
					}
	
				}
				//cout<<endl;
			}
			//cout<<endl;

			for(unsigned long i = 0; i<num_db_element; i++)
			{
				for(unsigned long j = 0; j< num_db_category + 1;j++)
				{
					if(j == 0)
					{
						cout<<datas[i];
					}
					else
					{
						cout<<"["<<data_orig[i][j-1]<<"]";
					}
				}
				cout<<endl;
			}

			//return dec_less_vec;
		}

		if(type == LEQ)
		{
	
			cout<<"less and equal vector"<<endl;
			vector<vector<ZZX>> less_equal_vec;
			less_equal_vec.resize(cipher_num);
			vector<vector<vector<ZZX>>> less_equal_result;
	
			num = 0;
			for(unsigned long i=0; i<cipher_num; i++)
			{
				for(unsigned long j=0; j<max_packed*comparator.m_expansionLen; j++)
				{
					num += 1;
					less_equal_vec[i].push_back(dec_less_vec[i][j] + dec_equal_vec[i][j]);
					printZZX(cout, less_equal_vec[i][j], ord_p);
					cout<<" ";
					if(num == num_db_element * comparator.m_expansionLen)
					{
						break;
					}
				}
			}
	
			cout<<endl;

			less_equal_result.resize(num_db_category);
			cout<<"less and equal result"<<endl;
			for(unsigned long i=0; i<num_db_category; i++)
			{
				less_equal_result[i].resize(cipher_num);
				num = 0;
				for(unsigned long j=0; j<cipher_num; j++)
				{
					for(unsigned long k=0; k<max_packed * comparator.m_expansionLen; k++)
					{
						less_equal_result[i][j].push_back(dec_eq_result[i][j][k] + dec_less_result[i][j][k]);
						printZZX(cout, less_equal_result[i][j][k], ord_p);
						cout<<" ";
						num += 1;
						if(num == num_db_element * comparator.m_expansionLen)
						{
							break;
						}
					}
	
				}
				cout<<endl;
			}
			cout<<endl;

			std::vector<std::vector<long>> data_orig;

			data_orig.resize(num_db_element);
			for(unsigned long i=0; i< num_db_element;i++)
			{
				data_orig[i].resize(num_db_category);
			}

			for(unsigned long i=0; i<num_db_category; i++)
			{
	
				num = 0;
				for(unsigned long j=0; j<cipher_num; j++)
				{
					for(unsigned long k=0; k< max_packed; k++)
					{
						data = 0;
						for(unsigned long l=0; l<comparator.m_expansionLen; l++)
						{
							coef = 0;
							for(long degr = 0; degr< deg(less_equal_result[i][j][k*comparator.m_expansionLen + l]) + 1; degr++)
							{
								coef += conv<long>(less_equal_result[i][j][k*comparator.m_expansionLen + l][degr]) * pow(enc_base, degr);
							}
							data += conv<long>(coef) * pow(digit_base, l);
						}
						//cout<<"["<<data<<"] ";
						data_orig[j*max_packed + k][i] = data;
						num += 1;
						if(num == num_db_element)
						{
							break;
						}
					}
	
				}
				//cout<<endl;
			}
			//cout<<endl;

			for(unsigned long i = 0; i<num_db_element; i++)
			{
				for(unsigned long j = 0; j< num_db_category + 1;j++)
				{
					if( j==0)
					{
						cout<<datas[i];
					}
					else
					{
						cout<<"["<<data_orig[i][j-1]<<"]";
					}
				}
				cout<<endl;
			}

			//return less_equal_vec;
		}
		//less final result
		//dec_less_vec	dec_less_result	  dec_eq_result	  dec_equal_vec
	};	

	void USER::EncryptNumber(Ctxt& ctxt, unsigned long input)
	{
		vector<ZZX> poly_input(nslots);
		input %= input_range;
		for (unsigned long i = 0; i < max_packed; ++i)
			dataToZZXSlot(input,
						  poly_input,
						  i,
						  digit_base,
						  exp_len,
						  enc_base,
						  comparator);
        contx.getView().encrypt(ctxt, pk, poly_input);
	}
		
	void USER::ConstructQuery(HEQuery& q,
							  unsigned long input,
					 		  Q_TYPE_t type,
					 		  unsigned long source,
							  vector<unsigned long> dest)  
	{
		Ctxt query_ctxt(pk);
		Ctxt eq(pk);
		Ctxt lt(pk);

		EncryptNumber(query_ctxt, input);
		if (type != LT) EncryptNumber(eq, 1);
		else EncryptNumber(eq, 0);
		if (type != EQ) EncryptNumber(lt, 1);
		else EncryptNumber(lt, 0);
		
		q.insert(source, eq, lt, query_ctxt, dest);
    };

	void USER::createPtxtIndexFile(string path)
	{
		vector<string> headers; // headers are column names
		CSVRange reader(*(new ifstream(path)));
		for (auto& row: reader)
        {
            for (unsigned int i = 1; i < row.size(); ++i)
                headers.emplace_back(row[i]);
            break;
        }
		int counter = 1;
		for (auto& row: reader)
		{
			for (unsigned int i = 1; i < row.size(); ++i) 
			{
				/* Index looks like [<key, [uid]>]
				 * Index File looks like [ <colname, Index> ]
				 */
				ptxt_index_file.insert(headers[i-1], stol(string{row[i]}), counter);
			}
			counter++;
		}
	}

	void USER::createCtxtIndexFile(HDB_supergate_::CtxtIndexFile& file)
	{
		file.encrypt(ptxt_index_file,
					 comparator,
					 contx,
					 pk,
					 input_range,
					 digit_base,
					 enc_base,
					 exp_len,
					 nslots,
					 max_packed,
					 verbose
					);
	}

	
    void USER::csvToDB(Ctxt_mat& db, string path, vector<string>& headers)
    {
        CSVRange reader(*(new ifstream(path)));
        for (auto& row: reader)
        {
            for (unsigned int i = 0; i < row.size(); ++i)
                headers.emplace_back(row[i]);
            break;
        }
        csvToDB(db, reader);
    }

    void USER::csvToDB(Ctxt_mat& db, string path)
    {
        CSVRange reader(*(new ifstream(path)));
        csvToDB(db, reader);
    }

    void USER::csvToDB(Ctxt_mat& db, CSVRange& reader) {
		vector<vector<ZZX>> ptxt_data;

		unsigned long counter = 0;

        for (auto& row: reader)
        {
			for (unsigned int i = 0; i < row.size(); ++i) 
			{
				if (!counter)
				{
					ptxt_data.emplace_back(*(new vector<ZZX>{nslots}));
				}
				dataToZZXSlot(stol(string{row[i]}) % input_range,
							  ptxt_data[i],
							  counter,
							  digit_base,
							  exp_len,
							  enc_base,
							  comparator);
			}
			counter++;
			if (counter == max_packed)
			{
				for (unsigned int i = 0; i < row.size(); ++i) 
				{
					if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
					encryptAndInsert(contx, pk, ptxt_data[i], db[i]);

				}
				counter = 0;
				ptxt_data.clear();
			}
        }
		if (counter > 0) 
		{
			for (unsigned int i = 0; i < ptxt_data.size(); ++i) 
			{
				if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
				encryptAndInsert(contx, pk, ptxt_data[i], db[i]);
			}
		}
		if (verbose)
			cout << "size: " << db.size() << "\n[0]size: " << db[0].size() << endl;
    }
}

