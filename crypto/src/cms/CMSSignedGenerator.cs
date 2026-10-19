using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    [Obsolete("Use 'Org.BouncyCastle.Operators.Utilities.DefaultSignatureAlgorithmFinder' instead")]
    /// <summary>Finds the signature AlgorithmIdentifier for a signature algorithm name.</summary>
    public class DefaultSignatureAlgorithmIdentifierFinder
        : Operators.Utilities.ISignatureAlgorithmFinder
    {
        // TODO[api] Make virtual
        /// <summary>Return the AlgorithmIdentifier for the named signature algorithm.</summary>
        /// <param name="sigAlgName">The signature algorithm name, for example "SHA256withRSA".</param>
        public AlgorithmIdentifier Find(string sigAlgName) =>
            Operators.Utilities.DefaultSignatureAlgorithmFinder.Instance.Find(sigAlgName);
    }

    [Obsolete("Use 'Org.BouncyCastle.Operators.Utilities.DefaultDigestAlgorithmFinder' instead")]
    /// <summary>Finds the digest AlgorithmIdentifier for a signature or digest algorithm.</summary>
    public class DefaultDigestAlgorithmIdentifierFinder
        : Operators.Utilities.IDigestAlgorithmFinder
    {
        // TODO[api] Make virtual
        /// <summary>Return the digest AlgorithmIdentifier used by the given signature algorithm.</summary>
        /// <param name="sigAlgId">The signature algorithm identifier.</param>
        public AlgorithmIdentifier Find(AlgorithmIdentifier sigAlgId) =>
            Operators.Utilities.DefaultDigestAlgorithmFinder.Instance.Find(sigAlgId);

        /// <summary>Return the AlgorithmIdentifier for the digest algorithm with the given object identifier.</summary>
        /// <param name="digAlgOid">The digest algorithm's object identifier.</param>
        public virtual AlgorithmIdentifier Find(DerObjectIdentifier digAlgOid) =>
            Operators.Utilities.DefaultDigestAlgorithmFinder.Instance.Find(digAlgOid);

        // TODO[api] Make virtual
        /// <summary>Return the AlgorithmIdentifier for the named digest algorithm.</summary>
        /// <param name="digAlgName">The digest algorithm name, for example "SHA-256".</param>
        public AlgorithmIdentifier Find(string digAlgName) =>
            Operators.Utilities.DefaultDigestAlgorithmFinder.Instance.Find(digAlgName);
    }

    /// <summary>Base class for generators of CMS signed data.</summary>
    /// <remarks>
    /// Certificates, CRLs and precalculated signers can be added to the generator before the message is produced.
    /// </remarks>
    public abstract class CmsSignedGenerator
    {
        /// <summary>Default type for the signed data.</summary>
        public static readonly string Data = CmsObjectIdentifiers.Data.Id;

        /// <summary>The object identifier (as a string) of the SHA-1 digest algorithm.</summary>
        public static readonly string DigestSha1 = OiwObjectIdentifiers.IdSha1.Id;
        /// <summary>The object identifier (as a string) of the SHA-224 digest algorithm.</summary>
        public static readonly string DigestSha224 = NistObjectIdentifiers.IdSha224.Id;
        /// <summary>The object identifier (as a string) of the SHA-256 digest algorithm.</summary>
        public static readonly string DigestSha256 = NistObjectIdentifiers.IdSha256.Id;
        /// <summary>The object identifier (as a string) of the SHA-384 digest algorithm.</summary>
        public static readonly string DigestSha384 = NistObjectIdentifiers.IdSha384.Id;
        /// <summary>The object identifier (as a string) of the SHA-512 digest algorithm.</summary>
        public static readonly string DigestSha512 = NistObjectIdentifiers.IdSha512.Id;
        /// <summary>The object identifier (as a string) of the SHA-512/224 digest algorithm.</summary>
        public static readonly string DigestSha512_224 = NistObjectIdentifiers.IdSha512_224.Id;
        /// <summary>The object identifier (as a string) of the SHA-512/256 digest algorithm.</summary>
        public static readonly string DigestSha512_256 = NistObjectIdentifiers.IdSha512_256.Id;

        /// <summary>The object identifier (as a string) of the SHA3-224 digest algorithm.</summary>
        public static readonly string DigestSha3_224 = NistObjectIdentifiers.IdSha3_224.Id;
        /// <summary>The object identifier (as a string) of the SHA3-256 digest algorithm.</summary>
        public static readonly string DigestSha3_256 = NistObjectIdentifiers.IdSha3_256.Id;
        /// <summary>The object identifier (as a string) of the SHA3-384 digest algorithm.</summary>
        public static readonly string DigestSha3_384 = NistObjectIdentifiers.IdSha3_384.Id;
        /// <summary>The object identifier (as a string) of the SHA3-512 digest algorithm.</summary>
        public static readonly string DigestSha3_512 = NistObjectIdentifiers.IdSha3_512.Id;

        /// <summary>The object identifier (as a string) of the SHAKE128 digest algorithm.</summary>
        public static readonly string DigestShake128 = NistObjectIdentifiers.IdShake128.Id;
        /// <summary>The object identifier (as a string) of the SHAKE256 digest algorithm.</summary>
        public static readonly string DigestShake256 = NistObjectIdentifiers.IdShake256.Id;

        /// <summary>The object identifier (as a string) of the MD5 digest algorithm.</summary>
        public static readonly string DigestMD5 = PkcsObjectIdentifiers.MD5.Id;
        /// <summary>The object identifier (as a string) of the GOST R 34.11-94 digest algorithm.</summary>
        public static readonly string DigestGost3411 = CryptoProObjectIdentifiers.GostR3411.Id;
        /// <summary>The object identifier (as a string) of the RIPEMD-128 digest algorithm.</summary>
        public static readonly string DigestRipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128.Id;
        /// <summary>The object identifier (as a string) of the RIPEMD-160 digest algorithm.</summary>
        public static readonly string DigestRipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160.Id;
        /// <summary>The object identifier (as a string) of the RIPEMD-256 digest algorithm.</summary>
        public static readonly string DigestRipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256.Id;
        /// <summary>The object identifier (as a string) of the SM3 digest algorithm.</summary>
        public static readonly string DigestSM3 = GMObjectIdentifiers.sm3.Id;

        /// <summary>The object identifier (as a string) of the RSA signature algorithm.</summary>
        public static readonly string EncryptionRsa = PkcsObjectIdentifiers.RsaEncryption.Id;
        /// <summary>The object identifier (as a string) of the DSA signature algorithm.</summary>
        public static readonly string EncryptionDsa = X9ObjectIdentifiers.IdDsaWithSha1.Id;
        /// <summary>The object identifier (as a string) of the ECDSA signature algorithm.</summary>
        public static readonly string EncryptionECDsa = X9ObjectIdentifiers.ECDsaWithSha1.Id;
        /// <summary>The object identifier (as a string) of the RSASSA-PSS signature algorithm.</summary>
        public static readonly string EncryptionRsaPss = PkcsObjectIdentifiers.IdRsassaPss.Id;
        /// <summary>The object identifier (as a string) of the GOST R 34.10-94 signature algorithm.</summary>
        public static readonly string EncryptionGost3410 = CryptoProObjectIdentifiers.GostR3410x94.Id;
        /// <summary>The object identifier (as a string) of the GOST R 34.10-2001 signature algorithm.</summary>
        public static readonly string EncryptionECGost3410 = CryptoProObjectIdentifiers.GostR3410x2001.Id;
        /// <summary>
        /// The object identifier (as a string) of the GOST R 34.10-2012 (256-bit) signature algorithm.
        /// </summary>
        public static readonly string EncryptionECGost3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id;
        /// <summary>
        /// The object identifier (as a string) of the GOST R 34.10-2012 (512-bit) signature algorithm.
        /// </summary>
        public static readonly string EncryptionECGost3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Id;

        internal List<Asn1Encodable> _certs = new List<Asn1Encodable>();
        internal List<Asn1Encodable> _crls = new List<Asn1Encodable>();
        internal List<SignerInformation> _signers = new List<SignerInformation>();
        internal Dictionary<DerObjectIdentifier, byte[]> m_digests = new Dictionary<DerObjectIdentifier, byte[]>();
        internal IDigestAlgorithmFinder m_digestAlgorithmFinder = DefaultDigestAlgorithmFinder.Instance;
        internal bool _useDerForCerts = false;
        internal bool _useDerForCrls = false;

        // TODO[api] Restrict to internal
        /// <summary>The source of randomness.</summary>
        protected readonly SecureRandom m_random;

        // TODO[api] Restrict to internal
        /// <summary>Create a generator using the default source of randomness.</summary>
        protected CmsSignedGenerator()
            : this(CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        // TODO[api] Restrict to internal
        protected CmsSignedGenerator(SecureRandom random)
        {
            m_random = random ?? throw new ArgumentNullException(nameof(random));
        }

        // TODO[api] After removing this, SignatureAlgorithmIdentifier can be assumed present in
        // DefaultSignedAttributeTableGenerator.AddMissingStandardAttributes
        [Obsolete("Will be removed")]
        /// <summary>Return the base parameters for attribute generation.</summary>
        /// <param name="contentType">The content type, or null.</param>
        /// <param name="digAlgId">The digest algorithm identifier.</param>
        /// <param name="hash">The digest of the content.</param>
        protected internal virtual IDictionary<CmsAttributeTableParameter, object> GetBaseParameters(
            DerObjectIdentifier contentType, AlgorithmIdentifier digAlgId, byte[] hash)
        {
            var param = new Dictionary<CmsAttributeTableParameter, object>();

            if (contentType != null)
            {
                param[CmsAttributeTableParameter.ContentType] = contentType;
            }

            param[CmsAttributeTableParameter.DigestAlgorithmIdentifier] = digAlgId;
            param[CmsAttributeTableParameter.Digest] = hash.Clone();

            return param;
        }

        internal virtual IDictionary<CmsAttributeTableParameter, object> GetBaseParameters(
            DerObjectIdentifier contentType, AlgorithmIdentifier digAlgID, AlgorithmIdentifier sigAlgID, byte[] hash)
        {
            var param = new Dictionary<CmsAttributeTableParameter, object>();

            if (contentType != null)
            {
                param[CmsAttributeTableParameter.ContentType] = contentType;
            }

            param[CmsAttributeTableParameter.DigestAlgorithmIdentifier] = digAlgID;
            param[CmsAttributeTableParameter.SignatureAlgorithmIdentifier] = sigAlgID;
            param[CmsAttributeTableParameter.Digest] = hash.Clone();

            return param;
        }

        // TODO[api] Restrict to internal
        /// <summary>Return the attributes as an ASN.1 set.</summary>
        /// <param name="attr">The attribute table, or null.</param>
        /// <returns>The set, or null if <paramref name="attr"/> is null.</returns>
        protected internal virtual Asn1Set GetAttributeSet(Asn1.Cms.AttributeTable attr)
        {
            return attr == null ? null : DerSet.FromCollection(attr);
        }

        /// <summary>Add an attribute certificate to the message.</summary>
        /// <param name="attrCert">The attribute certificate.</param>
        public void AddAttributeCertificate(X509V2AttributeCertificate attrCert) =>
            CmsUtilities.CollectAttributeCertificate(_certs, attrCert);

        /// <summary>Add the attribute certificates in the store to the message.</summary>
        /// <param name="attrCertStore">The store of attribute certificates.</param>
        public void AddAttributeCertificates(IStore<X509V2AttributeCertificate> attrCertStore) =>
            CmsUtilities.CollectAttributeCertificates(_certs, attrCertStore);

        /// <summary>Add a certificate to the message.</summary>
        /// <param name="cert">The certificate.</param>
        public void AddCertificate(X509Certificate cert) => CmsUtilities.CollectCertificate(_certs, cert);

        /// <summary>Add the certificates in the store to the message.</summary>
        /// <param name="certStore">The store of certificates.</param>
        public void AddCertificates(IStore<X509Certificate> certStore) =>
            CmsUtilities.CollectCertificates(_certs, certStore);

        /// <summary>Add a CRL to the message.</summary>
        /// <param name="crl">The CRL.</param>
        public void AddCrl(X509Crl crl) => CmsUtilities.CollectCrl(_crls, crl);

        /// <summary>Add the CRLs in the store to the message.</summary>
        /// <param name="crlStore">The store of CRLs.</param>
        public void AddCrls(IStore<X509Crl> crlStore) => CmsUtilities.CollectCrls(_crls, crlStore);

        /// <summary>Add other revocation information to the message.</summary>
        /// <param name="otherRevocationInfo">The revocation information.</param>
        public void AddOtherRevocationInfo(OtherRevocationInfoFormat otherRevocationInfo) =>
            CmsUtilities.CollectOtherRevocationInfo(_crls, otherRevocationInfo);

        /// <summary>Add other revocation information, in the given format, to the message.</summary>
        /// <param name="otherRevInfoFormat">The format of the information.</param>
        /// <param name="otherRevInfo">The information.</param>
        public void AddOtherRevocationInfo(DerObjectIdentifier otherRevInfoFormat, Asn1Encodable otherRevInfo) =>
            CmsUtilities.CollectOtherRevocationInfo(_crls, otherRevInfoFormat, otherRevInfo);

        /// <summary>Add the other revocation information in the store to the message.</summary>
        /// <param name="otherRevocationInfoStore">The store of revocation information.</param>
        public void AddOtherRevocationInfos(IStore<OtherRevocationInfoFormat> otherRevocationInfoStore) =>
            CmsUtilities.CollectOtherRevocationInfos(_crls, otherRevocationInfoStore);

        /// <summary>Add the other revocation information in the store, in the given format, to the message.</summary>
        /// <param name="otherRevInfoFormat">The format of the information.</param>
        /// <param name="otherRevInfoStore">The store of revocation information.</param>
        public void AddOtherRevocationInfos(DerObjectIdentifier otherRevInfoFormat,
            IStore<Asn1Encodable> otherRevInfoStore)
        {
            CmsUtilities.CollectOtherRevocationInfos(_crls, otherRevInfoFormat, otherRevInfoStore);
        }

        /// <summary>Add a store of precalculated signers to the generator.</summary>
        /// <param name="signerStore">store of signers</param>
        public void AddSigners(SignerInformationStore signerStore)
        {
            foreach (SignerInformation o in signerStore.SignersInternal)
            {
                _signers.Add(o);
                AddSignerCallback(o);
            }
        }

        /// <summary>Gets or sets the finder used to determine digest algorithm identifiers.</summary>
        public IDigestAlgorithmFinder DigestAlgorithmFinder
        {
            get { return m_digestAlgorithmFinder; }
            set { m_digestAlgorithmFinder = value ?? throw new ArgumentNullException(nameof(value)); }
        }

        /// <summary>
        /// Return a map of oids and byte arrays representing the digests calculated on the content during the last
        /// generate.
        /// </summary>
        /// <returns>a map of oids (as string objects) and byte[] representing digests.</returns>
        // TODO[api] Prefer to return just a copy of m_digests (i.e. keyed by DerObjectIdentifier)?
        public IDictionary<string, byte[]> GetGeneratedDigests()
        {
            var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in m_digests)
            {
                result.Add(entry.Key.GetID(), entry.Value);
            }
            return result;
        }

        [Obsolete("Will be removed. Replaced in CmsSignedDataGenerator by the similar 'UseDefiniteLength' property")]
        /// <summary>Gets or sets whether the certificates are DER encoded.</summary>
        public bool UseDerForCerts
        {
            get { return _useDerForCerts; }
            set { this._useDerForCerts = value; }
        }

        [Obsolete("Will be removed. Replaced in CmsSignedDataGenerator by the similar 'UseDefiniteLength' property")]
        /// <summary>Gets or sets whether the CRLs are DER encoded.</summary>
        public bool UseDerForCrls
        {
            get { return _useDerForCrls; }
            set { this._useDerForCrls = value; }
        }

        internal virtual void AddSignerCallback(SignerInformation signerInformation)
        {
        }

        internal static SignerIdentifier GetSignerIdentifier(X509Certificate c) => CmsUtilities.GetSignerIdentifier(c);

        internal static SignerIdentifier GetSignerIdentifier(byte[] subjectKeyIdentifier) =>
            CmsUtilities.GetSignerIdentifier(subjectKeyIdentifier);
    }
}
