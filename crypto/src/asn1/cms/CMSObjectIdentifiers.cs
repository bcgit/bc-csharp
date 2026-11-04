using System;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>Object identifiers for CMS (RFC 5652 and related standards).</summary>
    // TODO[api] Make static
    public abstract class CmsObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.2.840.113549.1.7.1</c>.</summary>
        public static readonly DerObjectIdentifier Data = PkcsObjectIdentifiers.Data;
        /// <summary>The object identifier <c>1.2.840.113549.1.7.2</c>.</summary>
        public static readonly DerObjectIdentifier SignedData = PkcsObjectIdentifiers.SignedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.7.3</c>.</summary>
        public static readonly DerObjectIdentifier EnvelopedData = PkcsObjectIdentifiers.EnvelopedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.7.4</c>.</summary>
        public static readonly DerObjectIdentifier SignedAndEnvelopedData = PkcsObjectIdentifiers.SignedAndEnvelopedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.7.5</c>.</summary>
        public static readonly DerObjectIdentifier DigestedData = PkcsObjectIdentifiers.DigestedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.7.6</c>.</summary>
        public static readonly DerObjectIdentifier EncryptedData = PkcsObjectIdentifiers.EncryptedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.2</c>.</summary>
        public static readonly DerObjectIdentifier AuthenticatedData = PkcsObjectIdentifiers.IdCTAuthData;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.9</c>.</summary>
        public static readonly DerObjectIdentifier CompressedData = PkcsObjectIdentifiers.IdCTCompressedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.23</c>.</summary>
        public static readonly DerObjectIdentifier AuthEnvelopedData = PkcsObjectIdentifiers.IdCTAuthEnvelopedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.31</c>.</summary>
        public static readonly DerObjectIdentifier TimestampedData = PkcsObjectIdentifiers.IdCTTimestampedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.3.8</c>.</summary>
        public static readonly DerObjectIdentifier ZlibCompress = PkcsObjectIdentifiers.IdAlgZlibCompress;

        /**
         * The other Revocation Info arc
         * id-ri OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
         *                                   dod(6) internet(1) security(5) mechanisms(5) pkix(7) ri(16) }
         */
        public static readonly DerObjectIdentifier id_ri = X509ObjectIdentifiers.IdPkix.Branch("16");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.16.2</c>.</summary>
        public static readonly DerObjectIdentifier id_ri_ocsp_response = id_ri.Branch("2");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.16.4</c>.</summary>
        public static readonly DerObjectIdentifier id_ri_scvp = id_ri.Branch("4");

        /** 1.3.6.1.5.5.7.6 */
        public static readonly DerObjectIdentifier id_alg = X509ObjectIdentifiers.pkix_algorithms;

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.30</c>.</summary>
        public static readonly DerObjectIdentifier id_RSASSA_PSS_SHAKE128 = X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE128;
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.31</c>.</summary>
        public static readonly DerObjectIdentifier id_RSASSA_PSS_SHAKE256 = X509ObjectIdentifiers.id_RSASSA_PSS_SHAKE256;
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.32</c>.</summary>
        public static readonly DerObjectIdentifier id_ecdsa_with_shake128 = X509ObjectIdentifiers.id_ecdsa_with_shake128;
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.33</c>.</summary>
        public static readonly DerObjectIdentifier id_ecdsa_with_shake256 = X509ObjectIdentifiers.id_ecdsa_with_shake256;

        /**
         * OtherRecipientInfo types
         */
        public static readonly DerObjectIdentifier id_ori = PkcsObjectIdentifiers.IdSmime.Branch("13");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.13.3</c>.</summary>
        public static readonly DerObjectIdentifier id_ori_kem = id_ori.Branch("3");

        /**
         *    id-alg-cek-hkdf-sha256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         *        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 31 }
         */
        public static readonly DerObjectIdentifier id_alg_cek_hkdf_sha256 =
            PkcsObjectIdentifiers.smime_alg.Branch("31");
    }
}
