
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
    USER::USER(Comparator & comparator, SecKey& sk) : comparator(comparator), sk(sk) {};

    /* Destruction */
    USER::~USER() {};

	unsigned long USER::max(){
		int space_bit_size = static_cast<int>(ceil(comparator.m_expansionLen*log2(digit_base)));

		unsigned long input_range = ULONG_MAX;
        if(space_bit_size < 64)
        {
            input_range = power_long(digit_base, comparator.m_expansionLen);
        }
		return input_range;
	};

	void USER::debug(Ctxt& ctxt, Comparator& comparator, SecKey& sk)
    {
        const EncryptedArray& ea = comparator.m_context.getEA();
        unsigned long ord_p = comparator.m_context.getOrdP();
        long nslots = ea.size();
        vector<ZZX> decrypted_cipher(nslots);
        ea.decrypt(ctxt, sk, decrypted_cipher);

        for(int i=0; i<nslots; i++)
        {
            printZZX(cout, decrypted_cipher[i], ord_p);
            if(decrypted_cipher[i] == ZZX(0))
            {
                cout<<" ";
            }
        }
        cout<<endl;
    };

    void USER::ShowRes(std::vector<ZZX> datas, Ctxt_vec &less_vector, Ctxt_vec &equal_vector, Ctxt_mat &equal_result, Ctxt_mat &less_result, unsigned long Row, unsigned long num_db_category, unsigned long num_db_element, Q_TYPE_t type)  
	{
		unsigned long cipher_num = Row/numbers_size;

		clock_t start, end;
	//	double result;

		start = clock();
		//equal vector decrypt
		vector<vector<ZZX>> dec_equal_vec;
		dec_equal_vec.resize(cipher_num);
		//cout<<"cipher_num: "<<cipher_num<<endl;


		for (int i=0; i<cipher_num ; i++)
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
		for(int i=0; i<cipher_num ; i++)
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
		for(int i=0; i< num_db_category; i++)
		{
			dec_eq_result[i].resize(cipher_num);
			for(int j = 0; j<cipher_num; j++)
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

		for(int i = 0; i<num_db_category; i++)
		{	
			dec_less_result[i].resize(cipher_num);
			for(int j = 0; j<cipher_num; j++)
			{	
				//cout<<less_result[i][j]<<" ";
				ea.decrypt(less_result[i][j], sk, dec_less_result[i][j]);
			}
			//cout<<endl;
		}

		ZZX *zero = new ZZX(0);
		ZZX *one = new ZZX(1);

		//less final vec and final result

		for(int i=0; i<cipher_num; i++)
        {   
            for(int j=0; j< numbers_size; j++)
            {   
                for(int k=0; k< comparator.m_expansionLen; k++)
                {   
                    if(dec_less_vec[i][j*comparator.m_expansionLen + k] == *zero && dec_equal_vec[i][j*comparator.m_expansionLen + k] == *one)
                    {   
						
                        dec_less_vec[i][j*comparator.m_expansionLen + k] = dec_equal_vec[i][j*comparator.m_expansionLen + k];

						for(int l=0; l<num_db_category; l++)
						{
							dec_less_result[l][i][j*comparator.m_expansionLen + k] = dec_eq_result[l][i][j*comparator.m_expansionLen + k];
						}
                    }
                }
            }
        }


		//equal final result
		for(int i=0; i<cipher_num; i++)
		{

			for(int j=0; j<numbers_size; j++)
			{
				int eq = 1;
				for(int k = 0; k<comparator.m_expansionLen-1;k++)
				{
					if(dec_equal_vec[i][j*comparator.m_expansionLen + k] != dec_equal_vec[i][j*comparator.m_expansionLen + k+1])
					{
						eq = 0;
					}
				}

				if(eq==0)
				{
					for(int k=0; k<comparator.m_expansionLen; k++)
					{	
						dec_equal_vec[i][j*comparator.m_expansionLen + k] = 0;
						for(int l= 0; l<num_db_category; l++)
						{
							dec_eq_result[l][i][j*comparator.m_expansionLen+k] = 0;
						}
					}
				}
			}
		}

		//less final result

		for(int i = 0; i<cipher_num; i++)
		{
			for(int j=0; j<nslots; j++)
			{
				if(dec_less_vec[i][j] == dec_equal_vec[i][j])
				{
					dec_less_vec[i][j] = 0;
					for(int k=0; k< num_db_category; k++)
					{
						dec_less_result[k][i][j] = 0;
					}
				}
			}
		}
		
		for(int i=0; i<cipher_num; i++)
		{
			for(int j=0; j<numbers_size; j++)
			{
				int eq = 1;
				for(int k=0; k<comparator.m_expansionLen-1; k++)
				{
					if(dec_less_vec[i][j*comparator.m_expansionLen + k] != dec_less_vec[i][j*comparator.m_expansionLen + k+1])
					{	
						eq = 0;
					}
				}

				if(eq==0)
				{
					for(int k=0;k<comparator.m_expansionLen;k++)
					{
						dec_less_vec[i][j*comparator.m_expansionLen+k] = 0;
						for(int l= 0; l< num_db_category;l++)
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
		int num = 0;
		long data;
		long coef;

		if(type == EQ)
		{
			cout<<"equal vector" <<endl;
			int num = 0;
			for(int i=0; i<cipher_num; i++)
			{
			    for(int j=0; j<numbers_size*comparator.m_expansionLen; j++)//deleted remaining slots in a ciphertext
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
			for(int i=0; i<num_db_category; i++)//print all columns
			{
				num = 0;
				for(int j=0; j<cipher_num; j++)
				{
					for(int k=0; k<numbers_size*comparator.m_expansionLen; k++)
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
			for(int i=0; i< num_db_element;i++)
			{
				data_orig[i].resize(num_db_category);
			}

			for(int i=0; i<num_db_category; i++)
			{		
				num = 0;
				for(int j=0; j<cipher_num; j++)
				{
					for(int k=0; k< numbers_size; k++)
					{
						data = 0;
						for(int l=0; l<comparator.m_expansionLen; l++)
						{
							coef = 0;
							for(int degr = 0; degr< deg(dec_eq_result[i][j][k*comparator.m_expansionLen + l]) + 1; degr++)
							{
								coef += conv<long>(dec_eq_result[i][j][k*comparator.m_expansionLen + l][degr]) * pow(enc_base, degr);
							}
							data += conv<long>(coef) * pow(digit_base, l);
						}
						//cout<<"["<<data<<"] ";
						data_orig[j*numbers_size + k][i] = data;
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
			
			for(int i = 0; i<num_db_element; i++)
			{
				for(int j = 0; j< num_db_category + 1;j++)
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
			for(int i=0; i<cipher_num; i++)
			{
				for(int j=0; j<numbers_size*comparator.m_expansionLen; j++)
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
			for(int i=0; i<num_db_category; i++)
	        {
				num = 0;
	            for(int j=0; j<cipher_num; j++)
	            {
	                for(int k=0; k<numbers_size*comparator.m_expansionLen; k++)
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
			for(int i=0; i< num_db_element;i++)
			{
				data_orig[i].resize(num_db_category);
			}

			//extended finite field -> number
			for(int i=0; i<num_db_category; i++)
			{
	
				num = 0;
				for(int j=0; j<cipher_num; j++)
				{
					for(int k=0; k< numbers_size; k++)
					{
						data = 0;
						for(int l=0; l<comparator.m_expansionLen; l++)
						{
							coef = 0;
							for(int degr = 0; degr< deg(dec_less_result[i][j][k*comparator.m_expansionLen + l]) + 1; degr++)
							{
								coef += conv<long>(dec_less_result[i][j][k*comparator.m_expansionLen + l][degr]) * pow(enc_base, degr);
							}
							data += conv<long>(coef) * pow(digit_base, l);
						}
						//cout<<"["<<data<<"] ";
						data_orig[j*numbers_size + k][i] = data;
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

			for(int i = 0; i<num_db_element; i++)
			{
				for(int j = 0; j< num_db_category + 1;j++)
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

		if(type == EL)
		{
	
			cout<<"less and equal vector"<<endl;
			vector<vector<ZZX>> less_equal_vec;
			less_equal_vec.resize(cipher_num);
			vector<vector<vector<ZZX>>> less_equal_result;
	
			num = 0;
			for(int i=0; i<cipher_num; i++)
			{
				for(int j=0; j<numbers_size*comparator.m_expansionLen; j++)
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
			for(int i=0; i<num_db_category; i++)
			{
				less_equal_result[i].resize(cipher_num);
				num = 0;
				for(int j=0; j<cipher_num; j++)
				{
					for(int k=0; k<numbers_size * comparator.m_expansionLen; k++)
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
			for(int i=0; i< num_db_element;i++)
			{
				data_orig[i].resize(num_db_category);
			}

			for(int i=0; i<num_db_category; i++)
			{
	
				num = 0;
				for(int j=0; j<cipher_num; j++)
				{
					for(int k=0; k< numbers_size; k++)
					{
						data = 0;
						for(int l=0; l<comparator.m_expansionLen; l++)
						{
							coef = 0;
							for(int degr = 0; degr< deg(less_equal_result[i][j][k*comparator.m_expansionLen + l]) + 1; degr++)
							{
								coef += conv<long>(less_equal_result[i][j][k*comparator.m_expansionLen + l][degr]) * pow(enc_base, degr);
							}
							data += conv<long>(coef) * pow(digit_base, l);
						}
						//cout<<"["<<data<<"] ";
						data_orig[j*numbers_size + k][i] = data;
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

			for(int i = 0; i<num_db_element; i++)
			{
				for(int j = 0; j< num_db_category + 1;j++)
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
		
	Ctxt USER::Query(int64_t q_id, Q_TYPE_t type)  
	{
		Ctxt query(comparator.m_pk);
		
		// Number should be handled
        int q_num = 1;

		int space_bit_size = static_cast<int>(ceil(comparator.m_expansionLen*log2(digit_base)));

		unsigned long input_range = ULONG_MAX;
		if(space_bit_size < 64)
		{
			input_range = power_long(digit_base, comparator.m_expansionLen);
		}

		long min_capacity = 1000;
		long capacity;

		vector<ZZX> pol_query(nslots);

		unsigned long input_query;
		ZZX pol_slot;
		for(int i=0; i<numbers_size;i++)
		{
			input_query = q_id % input_range;

			vector<long> decomp_int_query;

			digit_decomp(decomp_int_query, input_query, digit_base, comparator.m_expansionLen);
			
			for(int j=0; j<comparator.m_expansionLen; j++){
				comparator.int_to_slot(pol_slot, decomp_int_query[j], enc_base);
				pol_query[i*comparator.m_expansionLen + j] = pol_slot;
			}
		}

		for (int i = 0; i < q_num; i++) {
            ea.encrypt(query, comparator.m_pk, pol_query);
        }
		
        return query;
    };

	
    void USER::csvToDB(Ctxt_mat& db, string path, vector<string>& headers)
    {
        CSVRange reader(*(new ifstream(path)));
        for (auto& row: reader)
        {
            for (int i = 0; i < row.size(); ++i)
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
		int space_bit_size = static_cast<int>(ceil(exp_len * log2(digit_base)));
		
		unsigned long input_range = ULONG_MAX;
		if(space_bit_size < 64)
		{
			input_range = power_long(digit_base, exp_len);
		}
        
		long max_per = nslots / exp_len;
		vector<vector<ZZX>> ptxt_data;
		ZZX pol_slot;
		unsigned long input_data;
        vector<long> decomp_int_data;
		long counter = 0;

        for (auto& row: reader)
        {
			// cout << "for each row" << endl;
			for (int i = 0; i < row.size(); ++i) 
			{
				// cout << "for each column" << endl;
				if (!counter)
				{
					// cout << "!counter" << endl;
					ptxt_data.emplace_back(*(new vector<ZZX>{nslots}));
				}
				// cout << "input data: " << endl;
				input_data = stol(string{row[i]}) % input_range;
				// cout << input_data << endl;
				digit_decomp(decomp_int_data, input_data, digit_base, exp_len);
				// cout << "digit decomp" << endl;

				for(int l = 0; l < exp_len; ++l)
				{
					// cout << "for each l" << endl;
					comparator.int_to_slot(pol_slot, decomp_int_data[l], enc_base);
					ptxt_data[i][counter*exp_len + l] = pol_slot;
				}
			}
			// cout << "counter: " << counter << "max_per: " << max_per << endl;
			counter++;
			if (counter == max_per)
			{
				for (int i = 0; i < row.size(); ++i) 
				{
					Ctxt ctxt(comparator.m_pk);
					ea.encrypt(ctxt, comparator.m_pk, ptxt_data[i]);
					if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
					db[i].push_back(ctxt);
				}
				counter = 0;
				ptxt_data.clear();
			}
        }
		// cout << "counter: " << counter << endl;
		if (counter > 0) 
		{
			// cout << "looping for: " << ptxt_data.size() << endl;
			for (int i = 0; i < ptxt_data.size(); ++i) 
			{
				// cout << "i: " << i << endl;
				Ctxt ctxt(comparator.m_pk);
				ea.encrypt(ctxt, comparator.m_pk, ptxt_data[i]);
				if (db.size() < ptxt_data.size()) db.emplace_back(*(new vector<Ctxt>()));
				db[i].push_back(ctxt);
			}
		}
		cout << "size: " << db.size()
			 << "\n[0]size: " << db[0].size() << endl;
    }
}

