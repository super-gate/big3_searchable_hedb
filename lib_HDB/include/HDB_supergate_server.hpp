#ifndef HDB_supergate_server
#define HDB_supergate_server

#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

/**
 * \namespace HDB_supergate_server_
 * \brief Namespace for the SERVER class
*/
namespace HDB_supergate_server_{
    /**
     * \class SERVER
     * \brief Class that contains the DB and is queried upon
     * 
     * SERVER class contains the encrypted database and the encrypted index file. This simulates the REE.
    */
    class SERVER {
        private:
            he_cmp::Comparator& comparator;             /**< comparator object used for performing actual queries*/
            HDB_supergate_::Ctxt_mat& DB;               /**< the encrypted database in Ctxt_mat form */
            HDB_supergate_::CtxtIndexFile& IndexFile;   /**< the encrypted Index File */
            size_t Row;                                 /**< represents the number of rows in the DB */
            size_t Col;                                 /**< represents the number of columns in the DB */

            vector<helib::DoubleCRT> extractionMask;    /**< vector of all extraction masks to extract certain position's data */
            vector<double> extractionMaskSize;          /**< vector of extraction mask sizes */
        
            bool verbose;                               /**< flag for verbose execution */

            unsigned long nslots;
            unsigned long exp_len;
            unsigned long max_packed;
            unsigned long D;

            void create_all_extraction_masks();
            void create_extraction_mask(int);

        public:
            /**
             * Constructor of the SERVER class
             * @param comparator the reference to comparator class
             * @param db reference to the encrypted database
             * @param indFile reference to the encrypted index file
             * @param v verbose
            */
            explicit SERVER(he_cmp::Comparator& comparator,
                            HDB_supergate_::Ctxt_mat& db,
                            HDB_supergate_::CtxtIndexFile& indFile,
                            bool v);

            /**
             * \fn Query
             * \brief queries the DB and sends result back.
             * 
             * This function queries the database the "normal" way. It compares the source column with the query,
             * performs EQ/LT/LEQ query of it, and returns the destination columns. It returns the entire
             * destination column as query result.
             * 
             * @param query the query object of type HDB_supergate_::HEQuery
             * @param result the result of the query as type Ctxt_mat
             * 
             * @return void
            */
            void Query(HDB_supergate_::HEQuery& query, HDB_supergate_::Ctxt_mat& result);

            /**
             * \fn QueryWithIndex
             * \brief queries the DB using the index file and sends result back.
             * 
             * This function queries the database using the index file. It uses the index file search algorithm
             * to search corresponding results and populates the result with them. It returns Y, the number of
             * ciphertests in the Index's key, ciphertexts per destination column
             * 
             * @param query the query object of type HDB_supergate_::HEQuery
             * @param result the result of the query as type Ctxt_mat
             * 
             * @return void
            */
            void QueryWithIndex(HDB_supergate_::HEQuery& query, HDB_supergate_::Ctxt_mat& result);
    };
};

#endif


