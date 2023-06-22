#ifndef HDB_supergate_user
#define HDB_supergate_user

#include <helib/helib.h>
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include "HDB_supergate.hpp"

namespace HDB_supergate_user_{
    class USER {
        private:
        he_cmp::Comparator & comparator;
        helib::SecKey & sk;

        HDB_supergate_::PtxtIndexFile ptxt_index_file;
        
        const helib::EncryptedArray& ea = comparator.m_context.getEA();
        unsigned long p = comparator.m_context.getP();
        unsigned long ord_p = comparator.m_context.getOrdP();
        unsigned long nslots = ea.size();
        unsigned long exp_len = comparator.m_expansionLen;
        unsigned long max_packed = nslots / exp_len;
        unsigned long enc_base = (p + 1) >> 1; // UNI
        unsigned long digit_base = power_long(enc_base, comparator.m_slotDeg);
        int space_bit_size = static_cast<int>(ceil(exp_len * log2(digit_base)));
        unsigned long input_range = space_bit_size < 64 ? power_long(digit_base, exp_len) : ULONG_MAX;

        public:
        explicit USER(
            he_cmp::Comparator &comparator, 
            helib::SecKey &sk
        );

        ~USER();          
        
        unsigned long max();

        HDB_supergate_::PtxtIndexFile getPtxtIndexFile() {return ptxt_index_file;}
        void createPtxtIndexFile(string);

        void createCtxtIndexFile(HDB_supergate_::CtxtIndexFile&);

        helib::Ctxt Query(int64_t q_id, HDB_supergate_::Q_TYPE_t type);
                    
        void ShowRes(
            std::vector<NTL::ZZX> datas, 
            HDB_supergate_::Ctxt_vec &less_vector, 
            HDB_supergate_::Ctxt_vec &equal_vector, 
            HDB_supergate_::Ctxt_mat &equal_result, 
            HDB_supergate_::Ctxt_mat &less_result, 
            unsigned long Row, 
            unsigned long num_db_category, 
            unsigned long num_db_element, 
            HDB_supergate_::Q_TYPE_t type);

        void csvToDB(HDB_supergate_::Ctxt_mat&, 
                     HDB_supergate_::CSVRange&);

        void csvToDB(HDB_supergate_::Ctxt_mat&, 
                     std::string path);

        void csvToDB(HDB_supergate_::Ctxt_mat&, 
                     std::string path, 
                     std::vector<std::string>&);
        
        void printDecrypted(helib::Ctxt& ctxt);
        void printDB(HDB_supergate_::Ctxt_mat);
    };
};

#endif


