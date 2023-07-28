using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Isara;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    [Obsolete("Use 'Org.BouncyCastle.Operators.Utilities.DefaultSignatureAlgorithmFinder' instead")]
    public class DefaultSignatureAlgorithmIdentifierFinder
        : Operators.Utilities.ISignatureAlgorithmFinder
    {
        // TODO[api] Make virtual
        public AlgorithmIdentifier Find(string sigAlgName) =>
            Operators.Utilities.DefaultSignatureAlgorithmFinder.Instance.Find(sigAlgName);
    }

    [Obsolete("Use 'Org.BouncyCastle.Operators.Utilities.DefaultDigestAlgorithmFinder' instead")]
    public class DefaultDigestAlgorithmIdentifierFinder
        : Operators.Utilities.IDigestAlgorithmFinder
    {
        // TODO[api] Make virtual
        public AlgorithmIdentifier Find(AlgorithmIdentifier sigAlgId) =>
            Operators.Utilities.DefaultDigestAlgorithmFinder.Instance.Find(sigAlgId);

        public virtual AlgorithmIdentifier Find(DerObjectIdentifier digAlgOid) =>
            Operators.Utilities.DefaultDigestAlgorithmFinder.Instance.Find(digAlgOid);

        // TODO[api] Make virtual
        public AlgorithmIdentifier Find(string digAlgName) =>
            Operators.Utilities.DefaultDigestAlgorithmFinder.Instance.Find(digAlgName);
    }

    public abstract class CmsSignedGenerator
    {
        /**
        * Default type for the signed data.
        */
        public static readonly string Data = CmsObjectIdentifiers.Data.Id;

        public static readonly string DigestSha1 = OiwObjectIdentifiers.IdSha1.Id;
        public static readonly string DigestSha224 = NistObjectIdentifiers.IdSha224.Id;
        public static readonly string DigestSha256 = NistObjectIdentifiers.IdSha256.Id;
        public static readonly string DigestSha384 = NistObjectIdentifiers.IdSha384.Id;
        public static readonly string DigestSha512 = NistObjectIdentifiers.IdSha512.Id;
        public static readonly string DigestSha512_224 = NistObjectIdentifiers.IdSha512_224.Id;
        public static readonly string DigestSha512_256 = NistObjectIdentifiers.IdSha512_256.Id;
        public static readonly string DigestMD5 = PkcsObjectIdentifiers.MD5.Id;
        public static readonly string DigestGost3411 = CryptoProObjectIdentifiers.GostR3411.Id;
        public static readonly string DigestRipeMD128 = TeleTrusTObjectIdentifiers.RipeMD128.Id;
        public static readonly string DigestRipeMD160 = TeleTrusTObjectIdentifiers.RipeMD160.Id;
        public static readonly string DigestRipeMD256 = TeleTrusTObjectIdentifiers.RipeMD256.Id;

        public static readonly string EncryptionRsa = PkcsObjectIdentifiers.RsaEncryption.Id;
        public static readonly string EncryptionDsa = X9ObjectIdentifiers.IdDsaWithSha1.Id;
        public static readonly string EncryptionECDsa = X9ObjectIdentifiers.ECDsaWithSha1.Id;
        public static readonly string EncryptionRsaPss = PkcsObjectIdentifiers.IdRsassaPss.Id;
        public static readonly string EncryptionGost3410 = CryptoProObjectIdentifiers.GostR3410x94.Id;
        public static readonly string EncryptionECGost3410 = CryptoProObjectIdentifiers.GostR3410x2001.Id;
        public static readonly string EncryptionECGost3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id;
        public static readonly string EncryptionECGost3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Id;

        internal List<Asn1Encodable> _certs = new List<Asn1Encodable>();
        internal List<Asn1Encodable> _crls = new List<Asn1Encodable>();
        internal IList<SignerInformation> _signers = new List<SignerInformation>();
        internal IDictionary<string, byte[]> m_digests =
            new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        internal bool _useDerForCerts = false;
        internal bool _useDerForCrls = false;

        protected readonly SecureRandom m_random;

        protected CmsSignedGenerator()
            : this(CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        protected CmsSignedGenerator(SecureRandom random)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_random = random;
        }

        internal protected virtual IDictionary<CmsAttributeTableParameter, object> GetBaseParameters(
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

        internal protected virtual Asn1Set GetAttributeSet(
            Asn1.Cms.AttributeTable attr)
        {
            return attr == null
                ? null
                : DerSet.FromVector(attr.ToAsn1EncodableVector());
        }

        public void AddAttributeCertificate(X509V2AttributeCertificate attrCert)
        {
            _certs.Add(new DerTaggedObject(false, 2, attrCert.AttributeCertificate));
        }

        public void AddAttributeCertificates(IStore<X509V2AttributeCertificate> attrCertStore)
        {
            _certs.AddRange(CmsUtilities.GetAttributeCertificatesFromStore(attrCertStore));
        }

        public void AddCertificate(X509Certificate cert)
        {
            _certs.Add(cert.CertificateStructure);
        }

        public void AddCertificates(IStore<X509Certificate> certStore)
        {
            _certs.AddRange(CmsUtilities.GetCertificatesFromStore(certStore));
        }

        public void AddCrl(X509Crl crl)
        {
            _crls.Add(crl.CertificateList);
        }

        public void AddCrls(IStore<X509Crl> crlStore)
        {
            _crls.AddRange(CmsUtilities.GetCrlsFromStore(crlStore));
        }

        public void AddOtherRevocationInfo(OtherRevocationInfoFormat otherRevocationInfo)
        {
            CmsUtilities.ValidateOtherRevocationInfo(otherRevocationInfo);
            _crls.Add(new DerTaggedObject(false, 1, otherRevocationInfo));
        }

        public void AddOtherRevocationInfos(IStore<OtherRevocationInfoFormat> otherRevocationInfoStore)
        {
            _crls.AddRange(CmsUtilities.GetOtherRevocationInfosFromStore(otherRevocationInfoStore));
        }

        public void AddOtherRevocationInfos(DerObjectIdentifier otherRevInfoFormat,
            IStore<Asn1Encodable> otherRevInfoStore)
        {
            _crls.AddRange(CmsUtilities.GetOtherRevocationInfosFromStore(otherRevInfoStore, otherRevInfoFormat));
        }

        /**
		 * Add a store of precalculated signers to the generator.
		 *
		 * @param signerStore store of signers
		 */
        public void AddSigners(SignerInformationStore signerStore)
        {
            foreach (SignerInformation o in signerStore.GetSigners())
            {
                _signers.Add(o);
                AddSignerCallback(o);
            }
        }

        /**
		 * Return a map of oids and byte arrays representing the digests calculated on the content during
		 * the last generate.
		 *
		 * @return a map of oids (as string objects) and byte[] representing digests.
		 */
        public IDictionary<string, byte[]> GetGeneratedDigests()
        {
            return new Dictionary<string, byte[]>(m_digests, StringComparer.OrdinalIgnoreCase);
        }

        public bool UseDerForCerts
        {
            get { return _useDerForCerts; }
            set { this._useDerForCerts = value; }
        }

        public bool UseDerForCrls
        {
            get { return _useDerForCrls; }
            set { this._useDerForCrls = value; }
        }

        internal virtual void AddSignerCallback(
            SignerInformation si)
        {
        }

        internal static SignerIdentifier GetSignerIdentifier(X509Certificate cert)
        {
            return new SignerIdentifier(CmsUtilities.GetIssuerAndSerialNumber(cert));
        }

        internal static SignerIdentifier GetSignerIdentifier(byte[] subjectKeyIdentifier)
        {
            return new SignerIdentifier(new DerOctetString(subjectKeyIdentifier));
        }
    }
}
