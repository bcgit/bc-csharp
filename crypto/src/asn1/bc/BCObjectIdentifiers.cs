using System;

namespace Org.BouncyCastle.Asn1.BC
{
	public abstract class BCObjectIdentifiers
	{
        /**
         * iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
         * <p>1.3.6.1.4.1.22554</p>
         */
        public static readonly DerObjectIdentifier bc = new DerObjectIdentifier("1.3.6.1.4.1.22554");

        /**
         * pbe(1) algorithms
         * <p>1.3.6.1.4.1.22554.1</p>
         */
        public static readonly DerObjectIdentifier bc_pbe        = bc.Branch("1");

        /**
         * SHA-1(1)
         * <p>1.3.6.1.4.1.22554.1.1</p>
         */
        public static readonly DerObjectIdentifier bc_pbe_sha1   = bc_pbe.Branch("1");

        /** SHA-2.SHA-256; 1.3.6.1.4.1.22554.1.2.1 */
        public static readonly DerObjectIdentifier bc_pbe_sha256 = bc_pbe.Branch("2.1");
        /** SHA-2.SHA-384; 1.3.6.1.4.1.22554.1.2.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha384 = bc_pbe.Branch("2.2");
        /** SHA-2.SHA-512; 1.3.6.1.4.1.22554.1.2.3 */
        public static readonly DerObjectIdentifier bc_pbe_sha512 = bc_pbe.Branch("2.3");
        /** SHA-2.SHA-224; 1.3.6.1.4.1.22554.1.2.4 */
        public static readonly DerObjectIdentifier bc_pbe_sha224 = bc_pbe.Branch("2.4");

        /**
         * PKCS-5(1)|PKCS-12(2)
         */
        /** SHA-1.PKCS5;  1.3.6.1.4.1.22554.1.1.1 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs5    = bc_pbe_sha1.Branch("1");
        /** SHA-1.PKCS12; 1.3.6.1.4.1.22554.1.1.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12   = bc_pbe_sha1.Branch("2");

        /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.1 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs5  = bc_pbe_sha256.Branch("1");
        /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12 = bc_pbe_sha256.Branch("2");

        /**
         * AES(1) . (CBC-128(2)|CBC-192(22)|CBC-256(42))
         */
        /** 1.3.6.1.4.1.22554.1.1.2.1.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12_aes128_cbc   = bc_pbe_sha1_pkcs12.Branch("1.2");
        /** 1.3.6.1.4.1.22554.1.1.2.1.22 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12_aes192_cbc   = bc_pbe_sha1_pkcs12.Branch("1.22");
        /** 1.3.6.1.4.1.22554.1.1.2.1.42 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12_aes256_cbc   = bc_pbe_sha1_pkcs12.Branch("1.42");

        /** 1.3.6.1.4.1.22554.1.1.2.2.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12_aes128_cbc = bc_pbe_sha256_pkcs12.Branch("1.2");
        /** 1.3.6.1.4.1.22554.1.1.2.2.22 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12_aes192_cbc = bc_pbe_sha256_pkcs12.Branch("1.22");
        /** 1.3.6.1.4.1.22554.1.1.2.2.42 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12_aes256_cbc = bc_pbe_sha256_pkcs12.Branch("1.42");

        /**
         * signature(2) algorithms
         */
        public static readonly DerObjectIdentifier bc_sig        = bc.Branch("2");

        /**
         * Sphincs-256
         */
        public static readonly DerObjectIdentifier sphincs256                      = bc_sig.Branch("1");
        public static readonly DerObjectIdentifier sphincs256_with_BLAKE512        = sphincs256.Branch("1");
        public static readonly DerObjectIdentifier sphincs256_with_SHA512          = sphincs256.Branch("2");
        public static readonly DerObjectIdentifier sphincs256_with_SHA3_512        = sphincs256.Branch("3");

        /**
         * XMSS
         */
        public static readonly DerObjectIdentifier xmss                      = bc_sig.Branch("2");
        public static readonly DerObjectIdentifier xmss_with_SHA256          = xmss.Branch("1");
        public static readonly DerObjectIdentifier xmss_with_SHA512          = xmss.Branch("2");
        public static readonly DerObjectIdentifier xmss_with_SHAKE128        = xmss.Branch("3");
        public static readonly DerObjectIdentifier xmss_with_SHAKE256        = xmss.Branch("4");

        /**
         * XMSS^MT
         */
        public static readonly DerObjectIdentifier xmss_mt                      = bc_sig.Branch("3");
        public static readonly DerObjectIdentifier xmss_mt_with_SHA256          = xmss_mt.Branch("1");
        public static readonly DerObjectIdentifier xmss_mt_with_SHA512          = xmss_mt.Branch("2");
        public static readonly DerObjectIdentifier xmss_mt_with_SHAKE128        = xmss_mt.Branch("3");
        public static readonly DerObjectIdentifier xmss_mt_with_SHAKE256        = xmss_mt.Branch("4");
        
        /**
         * SPHINCS+
         */
        public static readonly DerObjectIdentifier sphincsPlus = bc_sig.Branch("5");
        public static readonly DerObjectIdentifier sphincsPlus_shake_256 = sphincsPlus.Branch("1");
        public static readonly DerObjectIdentifier sphincsPlus_sha_256 = sphincsPlus.Branch("2");
        public static readonly DerObjectIdentifier sphincsPlus_sha_512 = sphincsPlus.Branch("3");
        
        /**
         * Picnic
         */
        public static readonly DerObjectIdentifier picnic = bc_sig.Branch("6");
        public static readonly DerObjectIdentifier picnicl1fs = picnic.Branch("1");
        public static readonly DerObjectIdentifier picnicl1ur = picnic.Branch("2");
        public static readonly DerObjectIdentifier picnicl3fs = picnic.Branch("3");
        public static readonly DerObjectIdentifier picnicl3ur = picnic.Branch("4");
        public static readonly DerObjectIdentifier picnicl5fs = picnic.Branch("5");
        public static readonly DerObjectIdentifier picnicl5ur = picnic.Branch("6");
        public static readonly DerObjectIdentifier picnic3l1 = picnic.Branch("7");
        public static readonly DerObjectIdentifier picnic3l3 = picnic.Branch("8");
        public static readonly DerObjectIdentifier picnic3l5 = picnic.Branch("9");
        public static readonly DerObjectIdentifier picnicl1full = picnic.Branch("10");
        public static readonly DerObjectIdentifier picnicl3full = picnic.Branch("11");
        public static readonly DerObjectIdentifier picnicl5full = picnic.Branch("12");
        
        /*
         * Falcon
         */
        public static readonly DerObjectIdentifier falcon = bc_sig.Branch("7");

        public static readonly DerObjectIdentifier falcon_512 = new DerObjectIdentifier("1.3.9999.3.1");  // falcon.branch("1");
        public static readonly DerObjectIdentifier falcon_1024 =  new DerObjectIdentifier("1.3.9999.3.4"); // falcon.branch("2");

        /*
         * Dilithium
         */
        public static readonly DerObjectIdentifier dilithium = bc_sig.Branch("8");

        // OpenSSL OIDs
        public static readonly DerObjectIdentifier dilithium2 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.7.4.4"); // dilithium.branch("1");
        public static readonly DerObjectIdentifier dilithium3 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.7.6.5"); // dilithium.branch("2");
        public static readonly DerObjectIdentifier dilithium5 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.7.8.7"); // dilithium.branch("3");
        public static readonly DerObjectIdentifier dilithium2_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4"); // dilithium.branch("4");
        public static readonly DerObjectIdentifier dilithium3_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.11.6.5"); // dilithium.branch("5");
        public static readonly DerObjectIdentifier dilithium5_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.11.8.7"); // dilithium.branch("6");


        /**
         * key_exchange(3) algorithms
         */
        public static readonly DerObjectIdentifier bc_exch = bc.Branch("3");

        /**
         * NewHope
         */
        public static readonly DerObjectIdentifier newHope = bc_exch.Branch("1");

        /**
         * X.509 extension(4) values
         * <p/>
         * 1.3.6.1.4.1.22554.4
         */
        public static readonly DerObjectIdentifier bc_ext = bc.Branch("4");

        public static readonly DerObjectIdentifier linkedCertificate = bc_ext.Branch("1");

        /**
         * KEM(4) algorithms
         */
        public static readonly DerObjectIdentifier bc_kem = bc.Branch("5");

        /**
         * Classic McEliece
         */
        public static readonly DerObjectIdentifier pqc_kem_mceliece = bc_kem.Branch("1");

        public static readonly DerObjectIdentifier mceliece348864_r3 = pqc_kem_mceliece.Branch("1");
        public static readonly DerObjectIdentifier mceliece348864f_r3 = pqc_kem_mceliece.Branch("2");
        public static readonly DerObjectIdentifier mceliece460896_r3 = pqc_kem_mceliece.Branch("3");
        public static readonly DerObjectIdentifier mceliece460896f_r3 = pqc_kem_mceliece.Branch("4");
        public static readonly DerObjectIdentifier mceliece6688128_r3 = pqc_kem_mceliece.Branch("5");
        public static readonly DerObjectIdentifier mceliece6688128f_r3 = pqc_kem_mceliece.Branch("6");
        public static readonly DerObjectIdentifier mceliece6960119_r3 = pqc_kem_mceliece.Branch("7");
        public static readonly DerObjectIdentifier mceliece6960119f_r3 = pqc_kem_mceliece.Branch("8");
        public static readonly DerObjectIdentifier mceliece8192128_r3 = pqc_kem_mceliece.Branch("9");
        public static readonly DerObjectIdentifier mceliece8192128f_r3 = pqc_kem_mceliece.Branch("10");
        
        /**
         * SABER
         */
        public static readonly DerObjectIdentifier pqc_kem_saber = bc_kem.Branch("3");
        public static readonly DerObjectIdentifier lightsaberkem128r3 = pqc_kem_saber.Branch("1");
        public static readonly DerObjectIdentifier saberkem128r3 = pqc_kem_saber.Branch("2");
        public static readonly DerObjectIdentifier firesaberkem128r3 = pqc_kem_saber.Branch("3");
        public static readonly DerObjectIdentifier lightsaberkem192r3 = pqc_kem_saber.Branch("4");
        public static readonly DerObjectIdentifier saberkem192r3 = pqc_kem_saber.Branch("5");
        public static readonly DerObjectIdentifier firesaberkem192r3 = pqc_kem_saber.Branch("6");
        public static readonly DerObjectIdentifier lightsaberkem256r3 = pqc_kem_saber.Branch("7");
        public static readonly DerObjectIdentifier saberkem256r3 = pqc_kem_saber.Branch("8");
        public static readonly DerObjectIdentifier firesaberkem256r3 = pqc_kem_saber.Branch("9");
        public static readonly DerObjectIdentifier ulightsaberkemr3 = pqc_kem_saber.Branch("10");
        public static readonly DerObjectIdentifier usaberkemr3 = pqc_kem_saber.Branch("11");
        public static readonly DerObjectIdentifier ufiresaberkemr3 = pqc_kem_saber.Branch("12");
        public static readonly DerObjectIdentifier lightsaberkem90sr3 = pqc_kem_saber.Branch("13");
        public static readonly DerObjectIdentifier saberkem90sr3 = pqc_kem_saber.Branch("14");
        public static readonly DerObjectIdentifier firesaberkem90sr3 = pqc_kem_saber.Branch("15");
        public static readonly DerObjectIdentifier ulightsaberkem90sr3 = pqc_kem_saber.Branch("16");
        public static readonly DerObjectIdentifier usaberkem90sr3 = pqc_kem_saber.Branch("17");
        public static readonly DerObjectIdentifier ufiresaberkem90sr3 = pqc_kem_saber.Branch("18");

        /**
         * SIKE
         */
        public static readonly DerObjectIdentifier pqc_kem_sike = bc_kem.Branch("4");
        public static readonly DerObjectIdentifier sikep434 = pqc_kem_sike.Branch("1");
        public static readonly DerObjectIdentifier sikep503 = pqc_kem_sike.Branch("2");
        public static readonly DerObjectIdentifier sikep610 = pqc_kem_sike.Branch("3");
        public static readonly DerObjectIdentifier sikep751 = pqc_kem_sike.Branch("4");
        public static readonly DerObjectIdentifier sikep434_compressed = pqc_kem_sike.Branch("5");
        public static readonly DerObjectIdentifier sikep503_compressed = pqc_kem_sike.Branch("6");
        public static readonly DerObjectIdentifier sikep610_compressed = pqc_kem_sike.Branch("7");
        public static readonly DerObjectIdentifier sikep751_compressed = pqc_kem_sike.Branch("8");
        
        /**
         * Kyber
         */
        public static readonly DerObjectIdentifier pqc_kem_kyber = bc_kem.Branch("6");

        public static readonly DerObjectIdentifier kyber512 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.8.2.2"); // pqc_kem_kyber.Branch("1");
        public static readonly DerObjectIdentifier kyber768 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.8.3.3"); // pqc_kem_kyber.Branch("2");
        public static readonly DerObjectIdentifier kyber1024 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.8.4.4"); // pqc_kem_kyber.Branch("3");
        public static readonly DerObjectIdentifier kyber512_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.10.2.2"); // pqc_kem_kyber.Branch("4");
        public static readonly DerObjectIdentifier kyber768_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.10.3.3"); // pqc_kem_kyber.Branch("5");
        public static readonly DerObjectIdentifier kyber1024_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.10.4.4"); // pqc_kem_kyber.Branch("6");

        /**
         * BIKE
         */
        public static readonly DerObjectIdentifier pqc_kem_bike = bc_kem.Branch("8");

        public static readonly DerObjectIdentifier bike128 = pqc_kem_bike.Branch("1");
        public static readonly DerObjectIdentifier bike192 = pqc_kem_bike.Branch("2");
        public static readonly DerObjectIdentifier bike256 = pqc_kem_bike.Branch("3");

        /**
         * HQC
         */
        public static readonly DerObjectIdentifier pqc_kem_hqc = bc_kem.Branch("9");

        public static readonly DerObjectIdentifier hqc128 = pqc_kem_hqc.Branch("1");
        public static readonly DerObjectIdentifier hqc192 = pqc_kem_hqc.Branch("2");
        public static readonly DerObjectIdentifier hqc256 = pqc_kem_hqc.Branch("3");
    }
}
