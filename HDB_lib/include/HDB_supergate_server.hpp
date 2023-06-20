#ifndef HDB_supergate_server
#define HDB_supergate_server

#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

namespace HDB_supergate_server_{
    class SERVER {
        private:
        he_cmp::Comparator & comparator;

        HDB_supergate_::Ctxt_mat encrypted_DB;
        std::vector<std::pair<helib::Ctxt, HDB_supergate_::Ctxt_vec>> encrypted_index;
        HDB_supergate_::Ctxt_vec ctxt_equal;
        HDB_supergate_::Ctxt_vec less_final;

        unsigned long _num_db_element;
        unsigned long _num_db_category;
        unsigned long _max_element;
        unsigned long _Row;
       
        unsigned long numbers_size = comparator.m_context.getNSlots() / comparator.m_expansionLen;


        public:
        explicit SERVER (he_cmp::Comparator &comparator);
        ~SERVER();

        void Response(helib::Ctxt &query, HDB_supergate_::Q_TYPE_t, std::vector<long> q_cols);
        
        HDB_supergate_::Ctxt_vec less_vector();

        HDB_supergate_::Ctxt_vec equal_vector();

        HDB_supergate_::Ctxt_mat result_equal();

        HDB_supergate_::Ctxt_mat result_less();

        unsigned long row();

        unsigned long category();

        unsigned long element();
    };
};

#endif


