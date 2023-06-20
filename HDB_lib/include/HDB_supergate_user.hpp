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
        int _n; /*lattice dim*/
        int _q_log; /*lattice q*/
        uint32_t lambda; /*Security parameter*/
        
        const helib::EncryptedArray& ea = comparator.m_context.getEA();
        long nslots = ea.size();
        unsigned long p = comparator.m_context.getP();
        unsigned long ord_p = comparator.m_context.getOrdP();
        unsigned long numbers_size = comparator.m_context.getNSlots() / comparator.m_expansionLen;
        unsigned long enc_base = (p+1)>>1; // UNI
        unsigned long digit_base = power_long(enc_base, comparator.m_slotDeg);
        double result;


        public:
        explicit USER(
            he_cmp::Comparator &comparator, 
            helib::SecKey &sk
        );

        ~USER();          
        
        unsigned long max();

        Ctxt Query(int64_t q_id, HDB_supergate_::Q_TYPE_t type);
                    
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
        
        void debug(helib::Ctxt& ctxt, he_cmp::Comparator& comparator, helib::SecKey& sk);
    };
};

#endif


