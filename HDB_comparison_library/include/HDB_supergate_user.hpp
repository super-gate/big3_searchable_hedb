#ifndef HDB_supergate_user
#define HDB_supergate_user

#include <helib/helib.h>
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include "HDB_supergate.hpp"

/**
 * \namespace HDB_supergate_user_
 * \brief Namespace for the USER class
*/
namespace HDB_supergate_user_{
    /**
     * \class USER
     * \brief Class that simulates the USER that queries the DB
     * 
     * USER class simulates the TEE and contains both public and secret keys. It can construct query objects
     * and encrypt plaintext database to send to the SERVER class. 
    */
    class USER {
        public:
        std::unique_ptr<he_cmp::Comparator> Comp;                                                     /**< comparator object */
        std::unique_ptr<helib::Context> Contx;                                                        /**< crypto-context */
        std::unique_ptr<helib::PubKey> PublicKey;                                                                  /**< public key */
        std::unique_ptr<helib::SecKey> SecretKey;                                                                  /**< secret key */

        HDB_supergate_::PtxtIndexFile ptxt_index_file;                                      /**< the plaintext index file*/
        
        std::unique_ptr<const helib::EncryptedArray> ea;                                  /**< encrypted array class used to encrypt and decrypt ciphertexts*/
        unsigned long p;                                                     /**< plaintext modulus p */
        unsigned long ord_p;                                              /**< multiplicative order of p mod m */
        unsigned long D;                                             /**< extension field degree*/
        unsigned long nslots;                                           /**< number of slots for this context */
        unsigned long exp_len;                                  /**< the expansion length l */
        unsigned long max_packed;                                        /**< number of data that can be packed in a single ciphertext */
        unsigned long enc_base;                                              /**< encryption base. (p+1)/2 for univariate circuit */
        unsigned long digit_base;              /**< the actual digit base after d*/
        int space_bit_size;            /**< the bit size of the current context*/
        unsigned long input_range;   /**< the maximum input current context can handle*/

        bool verbose;                                                                       /**< verbose flag */

        /**
         * \fn EncryptNumber
         * \brief Creates a ciphertext with slots filled with the specified integer. Creates E(N) for N.
         * 
         * @param ctxt ciphertext that is populated
         * @param i integer to be inserted
        */
        void EncryptNumber(helib::Ctxt& ctxt, unsigned long i);
        void EncryptNumberPerSlot(helib::Ctxt& ctxt, long i);

        void saveInfo(HDB_supergate_::BGV_param param);                                                /**< serializes contx, pubkey, seckey */
        void constructPathName(HDB_supergate_::BGV_param param, std::string&);
        void HandleSecKey(HDB_supergate_::BGV_param);
        void HandlePubKey();

        int8_t loadContext(std::string);
        int8_t loadPubKey(std::string);
        int8_t loadComparator(HDB_supergate_::BGV_param param);
        int8_t loadSecKey(std::string);
        void loadRest(std::string, HDB_supergate_::BGV_param param);
        int8_t loadEncryptionInfo(HDB_supergate_::BGV_param);
        void getCSVHeaders(std::string path, std::vector<std::string>& headers);

        void DestroyKeys();
        void ClearInfo();

        /**
         * \fn createPtxtIndexFile
         * \brief parses the csv from filename and constructs a PtxtIndexFile object
         * 
         * @param filename file path to the raw csv data
        */
        void createPtxtIndexFile(string filename);
        /**
         * \fn createCtxtIndexFile
         * \brief encrypts the PtxtIndexFile into CtxtIndexFile
         * 
         * @param IndexFile reference to the CtxtIndexFile to be populated
        */
        void createCtxtIndexFile(HDB_supergate_::CtxtIndexFile& IndexFile);

        /**
         * \fn ConstructQuery
         * \brief constructs a query object based on parameters
         * 
         * @param query reference to the query object to be populated
         * @param input the input integer query
         * @param type the type of the query to be executed in enum Q_TYPE_t
         * @param source the integer index of source column to be queried from
         * @param dest vector of integer indices of destination columns to be queried
        */
        HDB_supergate_::HEQuery* ConstructQuery(HDB_supergate_::BGV_param param,
                                                unsigned long input,
                                                HDB_supergate_::Q_TYPE_t type,
                                                long source, //TODO: change this to query names from just indices maybe?
                                                std::vector<long> dest);

        /**
         * \fn csvToDB
         * \brief function to encrypt all plaintext data into ciphertext and save into a Ctxt_mat datatype
         * 
         * @param DB the referecnce to the Ctxt_mat datatype we are saving all ciphertext into
         * @param range the CSVRange object that reads the csvfile
        */
        void csvToDB(HDB_supergate_::Ctxt_mat& DB, 
                     HDB_supergate_::CSVRange& range);

        /**
         * used to convert csv files without headers
         * @param DB the referecnce to the Ctxt_mat datatype we are saving all ciphertext into
         * @param path file path of the csv file
        */
        void csvToDB(HDB_supergate_::Ctxt_mat& DB, 
                     std::string path);

        /**
         * used to convert csv files with headers into ciphertext DB
         * @param DB the referecnce to the Ctxt_mat datatype we are saving all ciphertext into
         * @param path file path of the csv file
         * @param headers reference to the container of headers
        */
        void csvToDB(HDB_supergate_::Ctxt_mat& DB, 
                     std::string path, 
                     std::vector<std::string>& headers);

        public:
        /**
         * (Deprecated) Constructor for the USER class
         * @deprecated
         * @param comparator reference to comparator object
         * @param contx reference to the crypto-context
         * @param pk reference to the public key object
         * @param sk reference to the secret key object
         * @param verbose verbose flag
        */
        USER(he_cmp::Comparator& comparator,
             helib::Context& contx,
             helib::PubKey& pk,
             helib::SecKey& sk,
             bool
        );
        
        /**
         * Constructor for USER class
         * @param verbose verbose flag
        */
        USER(bool verbose);

        std::pair<helib::PubKey, helib::SecKey> generateKeys(helib::Context* contx, HDB_supergate_::BGV_param param);
        void EncryptData(std::string path,
                         HDB_supergate_::BGV_param param,
                         HDB_supergate_::Ctxt_mat& db,
                         std::vector<std::string>& headers,
                         HDB_supergate_::CtxtIndexFile& indFile,
                         bool index);

        unsigned long max();                                                            /**< returns input_range */

        HDB_supergate_::PtxtIndexFile getPtxtIndexFile() {return ptxt_index_file;}      /**< returns the plaintext index file */
        int8_t loadDecryptionInfo(HDB_supergate_::BGV_param);                           /**< ONLY FOR DEBUGGING PURPOSES */
        void printQueryResult(HDB_supergate_::BGV_param,                                /**< main function to decrpt and print ciphertext */
                              HDB_supergate_::Ctxt_mat&,
                              HDB_supergate_::Q_MODE);
        void printZZXasINT(vector<ZZX>);                                                /**< debug function to print ZZX type as integer */
        void printPackedZZXasINT(vector<ZZX>);                                          /**< debug function to print extension field packed ZZX as integers*/
        void printDecryptedINT(helib::Ctxt& ctxt, bool zzx_packed = false);             /**< debug function to decrypt and print the ciphertext as integer*/
        void printDecryptedZZX(helib::Ctxt& ctxt);                                      /**< debug function to decrypt and print ciphertext as ZZX*/
        void printCtxtVecINT(HDB_supergate_::Ctxt_vec&, bool zzx_packed = false);       /**< debug function to decrypt and print Ctxt_vec type object as integer*/
        void printCtxtVecZZX(HDB_supergate_::Ctxt_vec&);                                /**< debug function to decrypt and print Ctxt_vec type object as ZZX*/
        void printCtxtMatINT(HDB_supergate_::Ctxt_mat&, bool zzx_packed = false);       /**< debug function to decrypt and print a Ctxt_mat type object as integer*/
        void printCtxtMatZZX(HDB_supergate_::Ctxt_mat&);                                /**< debug function to decrypt and print a Ctxt_mat type object as ZZX*/
    };
};

#endif


