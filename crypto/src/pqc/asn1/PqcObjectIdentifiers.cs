using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;

namespace Org.BouncyCastle.Pqc.Asn1
{
    public static class PqcObjectIdentifiers
    {
        /** 1.3.6.1.4.1.8301.3.1.3.5.3.2 */
        public static readonly DerObjectIdentifier rainbow = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");

        /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.1 */
        public static readonly DerObjectIdentifier rainbowWithSha1   = rainbow.Branch("1");
        /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.2 */
        public static readonly DerObjectIdentifier rainbowWithSha224 = rainbow.Branch("2");
        /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.3 */
        public static readonly DerObjectIdentifier rainbowWithSha256 = rainbow.Branch("3");
        /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.4 */
        public static readonly DerObjectIdentifier rainbowWithSha384 = rainbow.Branch("4");
        /** 1.3.6.1.4.1.8301.3.1.3.5.3.2.5 */
        public static readonly DerObjectIdentifier rainbowWithSha512 = rainbow.Branch("5");

        /** 1.3.6.1.4.1.8301.3.1.3.3 */
        public static readonly DerObjectIdentifier gmss = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.3");

        /** 1.3.6.1.4.1.8301.3.1.3.3.1 */
        public static readonly DerObjectIdentifier gmssWithSha1   = gmss.Branch("1");
        /** 1.3.6.1.4.1.8301.3.1.3.3.2 */
        public static readonly DerObjectIdentifier gmssWithSha224 = gmss.Branch("2");
        /** 1.3.6.1.4.1.8301.3.1.3.3.3 */
        public static readonly DerObjectIdentifier gmssWithSha256 = gmss.Branch("3");
        /** 1.3.6.1.4.1.8301.3.1.3.3.4 */
        public static readonly DerObjectIdentifier gmssWithSha384 = gmss.Branch("4");
        /** 1.3.6.1.4.1.8301.3.1.3.3.5 */
        public static readonly DerObjectIdentifier gmssWithSha512 = gmss.Branch("5");

        /** 1.3.6.1.4.1.8301.3.1.3.4.1 */
        public static readonly DerObjectIdentifier mcEliece       = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");

        /** 1.3.6.1.4.1.8301.3.1.3.4.2 */
        public static readonly DerObjectIdentifier mcElieceCca2   = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");

        /// <summary>The object identifier <c>1.3.6.1.4.1.8301.3.1.3.4.2.1</c>.</summary>
        public static readonly DerObjectIdentifier mcElieceFujisaki    = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.1");
        /// <summary>The object identifier <c>1.3.6.1.4.1.8301.3.1.3.4.2.2</c>.</summary>
        public static readonly DerObjectIdentifier mcEliecePointcheval = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.2");
        /// <summary>The object identifier <c>1.3.6.1.4.1.8301.3.1.3.4.2.3</c>.</summary>
        public static readonly DerObjectIdentifier mcElieceKobara_Imai = new DerObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.3");

#pragma warning disable CS0618 // Type or member is obsolete
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.1</c>.</summary>
        [Obsolete("Will be removed")]
        public static readonly DerObjectIdentifier sphincs256 = BCObjectIdentifiers.sphincs256;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.1.1</c>.</summary>
        [Obsolete("Will be removed")]
        public static readonly DerObjectIdentifier sphincs256_with_BLAKE512 = BCObjectIdentifiers.sphincs256_with_BLAKE512;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.1.2</c>.</summary>
        [Obsolete("Will be removed")]
        public static readonly DerObjectIdentifier sphincs256_with_SHA512 = BCObjectIdentifiers.sphincs256_with_SHA512;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.1.3</c>.</summary>
        [Obsolete("Will be removed")]
        public static readonly DerObjectIdentifier sphincs256_with_SHA3_512 = BCObjectIdentifiers.sphincs256_with_SHA3_512;
#pragma warning restore CS0618 // Type or member is obsolete

        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.3.1</c>.</summary>
        public static readonly DerObjectIdentifier newHope = BCObjectIdentifiers.newHope;

        /**
         * XMSS
         */
        public static readonly DerObjectIdentifier xmss                      = BCObjectIdentifiers.xmss;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.1</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHA256ph             = BCObjectIdentifiers.xmss_SHA256ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.2</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHA512ph             = BCObjectIdentifiers.xmss_SHA512ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.9</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHAKE128ph           = BCObjectIdentifiers.xmss_SHAKE128ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.10</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHAKE256ph           = BCObjectIdentifiers.xmss_SHAKE256ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.5</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHA256               = BCObjectIdentifiers.xmss_SHA256;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.6</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHA512               = BCObjectIdentifiers.xmss_SHA512;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.7</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHAKE128             = BCObjectIdentifiers.xmss_SHAKE128;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.2.8</c>.</summary>
        public static readonly DerObjectIdentifier xmss_SHAKE256             = BCObjectIdentifiers.xmss_SHAKE256;


        /**
         * XMSS^MT
         */
        public static readonly DerObjectIdentifier xmss_mt                   = BCObjectIdentifiers.xmss_mt;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.1</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHA256ph          = BCObjectIdentifiers.xmss_mt_SHA256ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.2</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHA512ph          = BCObjectIdentifiers.xmss_mt_SHA512ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.9</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHAKE128ph        = BCObjectIdentifiers.xmss_mt_SHAKE128ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.10</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHAKE256ph        = BCObjectIdentifiers.xmss_mt_SHAKE256ph;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.5</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHA256            = BCObjectIdentifiers.xmss_mt_SHA256;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.6</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHA512            = BCObjectIdentifiers.xmss_mt_SHA512;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.7</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHAKE128          = BCObjectIdentifiers.xmss_mt_SHAKE128;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.3.8</c>.</summary>
        public static readonly DerObjectIdentifier xmss_mt_SHAKE256          = BCObjectIdentifiers.xmss_mt_SHAKE256;

        /**
         * qTESLA
         */
        public static readonly DerObjectIdentifier qTESLA = BCObjectIdentifiers.qTESLA;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.4.11</c>.</summary>
        public static readonly DerObjectIdentifier qTESLA_p_I = BCObjectIdentifiers.qTESLA_p_I;
        /// <summary>The object identifier <c>1.3.6.1.4.1.22554.2.4.12</c>.</summary>
        public static readonly DerObjectIdentifier qTESLA_p_III = BCObjectIdentifiers.qTESLA_p_III;

        /**
         * Explicit composite algorithms
         */
        public static readonly DerObjectIdentifier id_Dilithium3_RSA_PKCS15_SHA256 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.1");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_Dilithium3_ECDSA_P256_SHA256 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.2");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.3</c>.</summary>
        public static readonly DerObjectIdentifier id_Dilithium3_ECDSA_brainpoolP256r1_SHA256 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.3");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.4</c>.</summary>
        public static readonly DerObjectIdentifier id_Dilithium3_Ed25519 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.4");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.5</c>.</summary>
        public static readonly DerObjectIdentifier id_Dilithium5_ECDSA_P384_SHA384 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.5");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.6</c>.</summary>
        public static readonly DerObjectIdentifier id_Dilithium5_ECDSA_brainpoolP384r1_SHA384 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.6");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.7</c>.</summary>
        public static readonly DerObjectIdentifier id_Dilithium5_Ed448 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.7");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.8</c>.</summary>
        public static readonly DerObjectIdentifier id_Falcon512_ECDSA_P256_SHA256 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.8");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.9</c>.</summary>
        public static readonly DerObjectIdentifier id_Falcon512_ECDSA_brainpoolP256r1_SHA256 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.9");
        /// <summary>The object identifier <c>2.16.840.1.114027.80.5.1.10</c>.</summary>
        public static readonly DerObjectIdentifier id_Falcon512_Ed25519 = new DerObjectIdentifier("2.16.840.1.114027.80.5.1.10");
    }
}
