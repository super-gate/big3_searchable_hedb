#ifndef HDB_supergate_server
#define HDB_supergate_server

#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

#include <optional>

/**
 * \namespace HDB_supergate_server_
 * \brief Namespace for the SERVER class
*/
namespace HDB_supergate_server_{
    /**
     * \class SERVER
     * \brief Class that contains the HEDB and is queried upon
     * 
     * SERVER class contains the encrypted database and the encrypted index file. This simulates the REE.
    */
    class SERVER {
        private:
            std::unique_ptr<he_cmp::Comparator> Comp;                 /**< comparator object used for performing actual queries*/
            std::unique_ptr<helib::Context> Contx;
            std::unique_ptr<helib::PubKey> PublicKey;
            std::string currDBName = "";                    /**< Currently loaded DB name */
            HDB_supergate_::BGV_param currParam;            /**< Currently loaded BGV parameters */
            std::unique_ptr<HDB_supergate_::Ctxt_mat> Database;                   /**< the encrypted database in Ctxt_mat form */
            std::unique_ptr<HDB_supergate_::CtxtIndexFile> IndexFile;       /**< the encrypted Index File */
            size_t Row;                                     /**< represents the number of rows in the DB */
            size_t Col;                                     /**< represents the number of columns in the DB */

            vector<helib::DoubleCRT> extractionMask;        /**< vector of all extraction masks to extract certain position's data */
            vector<double> extractionMaskSize;              /**< vector of extraction mask sizes */
        
            bool verbose;                                   /**< flag for verbose execution */

            unsigned long nslots;                           /**< number of slots per ciphertext */
            unsigned long exp_len;                          /**< expansion length l*/
            unsigned long max_packed;                       /**< maximum numbers packed per ciphertext */
            unsigned long D;                                /**< expansion degree d*/

            void create_all_extraction_masks();             /**< function creates all extraciton masks*/
            void create_extraction_mask(int);               /**< function creates one extraction mask e1_j given position j*/
            void totalSums(Ctxt&,                           /**< function for total sum with exp_len */
                           unsigned long, 
                           unsigned long);                  
            void constructDBPath(std::string,               /**< helper function to create the DB path from db_name and bgv parameters*/
                                 HDB_supergate_::BGV_param,
                                 std::string&);

            int8_t loadContext(std::string);
            int8_t loadPubKey(std::string);
            int8_t loadComparator(HDB_supergate_::BGV_param);
            int8_t loadDB(std::string);
            int8_t loadIndexFile(std::string);
            void loadRest(std::string, HDB_supergate_::BGV_param);
            
            /**
             * \fn LoadData
             * \brief Loads the Database specified by db_name and encryption parameters
             * 
             * This function reads the filesystem and loads the encrypted database into RAM. According to the boolean flag, it 
             * also reads the indexFile and loads it.
             * 
             * @param db_name the db name we are looking for
             * @param param the bgv parameters the DB is encrpyted in
             * @param ind boolean flag whether we load in the index file or not
             * 
             * @return 0 on success, -1 on failure
            */
            int8_t LoadData(std::string db_name, HDB_supergate_::BGV_param param, bool ind);

        public:

            SERVER() {};
            /**
             * Constructor of the SERVER class without index file or db auto-filled
             * @param comparator the reference to comparator class
             * @param v verbose flag
            */
            SERVER(bool v);

            /**
             * (Deprecated) Constructor of the SERVER class
             * @deprecated
             * @param comparator the reference to comparator class
             * @param db reference to the encrypted database
             * @param indFile reference to the encrypted index file
             * @param v verbose flag
            */
            SERVER(he_cmp::Comparator& comparator,
                   HDB_supergate_::Ctxt_mat& db,
                   HDB_supergate_::CtxtIndexFile& indFile,
                   bool v);

            /**
             * \fn SaveDB
             * \brief Saves the database with its context, pubkey, indexfile if exists
             * 
             * This function saves the database to the filesystem accoridng to the db_name. It also saves the index file
             * if the optional results to be non-null.
             * 
             * @param db_name the db name
             * @param param BGV parameters the DB is encrypted with
             * @param contx the Crypto context
             * @param pk the Public Key
             * @param db the db
             * @param indFile (optional) index file
             * 
             * @return void
            */
            void SaveDB(std::string db_name, 
                        HDB_supergate_::BGV_param param, 
                        helib::Context& contx,
                        helib::PubKey& pk,
                        HDB_supergate_::Ctxt_mat& db, 
                        std::optional<HDB_supergate_::CtxtIndexFile>& indFile);

            HDB_supergate_::HEQuery deserializeQuery(std::istream& is);
            
            /**
             * \fn ProcessQuery
             * \brief Clears and populates DB, queries, and fills result Ctxt_mat with results
             * 
             * This function is the main entry-point for queries. It takes in db_name as a parameter to search for 
             * which DB the query is referring to, the query mode (normal, extension field, index), the query object,
             * and result. It calls the three different query routines according to mode.
             * 
             * @param db_name the DB that query wants to look into
             * @param param the BGV params that the query is encrypted with, and the queried DB should be encrypted with
             * @param mode enum of query mode
             * @param query the query object
             * @param result result of query to be saved into
             * 
             * @return 0 on success, -1 on failure
            */
            int8_t ProcessQuery(std::string db_name, 
                                HDB_supergate_::BGV_param param, 
                                HDB_supergate_::Q_MODE mode, 
                                HDB_supergate_::HEQuery& query,
                                HDB_supergate_::Ctxt_mat& result);

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
             * \fn QueryExtensionField
             * \brief queries the DB and uses the extension field method to send result back
             * 
             * This function queries the database using the extension fields to compress the ciphertext data as
             * much as possible. Supports EQ/LT/LEQ queries. The result is compressed by a factor of 
             * ordP / D
             * 
             * @param query the query object of type HDB_supergate_::HEQuery
             * @param result the result of the query as type Ctxt_mat
             * 
             * @return void
            */
            void QueryExtensionField(HDB_supergate_::HEQuery& query, HDB_supergate_::Ctxt_mat& result);

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

            void testTS(Ctxt&); /**< debugging function for SERVER::totalSums */
    };
};

#endif


