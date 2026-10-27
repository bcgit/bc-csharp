using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>General class for handling a PKCS #7 / CMS signed-data message.</summary>
    /// <example>
    /// A simple example of usage. Note that the validity of the certificate isn't verified here, just the fact that
    /// one of the certificates matches the given signer:
    /// <code>
    /// IStore&lt;X509Certificate&gt; certs = s.GetCertificates();
    /// SignerInformationStore signers = s.GetSignerInfos();
    ///
    /// foreach (SignerInformation signer in signers)
    /// {
    ///     var certList = new List&lt;X509Certificate&gt;(certs.EnumerateMatches(signer.SignerID));
    ///     X509Certificate cert = certList[0];
    ///
    ///     if (signer.Verify(cert))
    ///     {
    ///         verified++;
    ///     }
    /// }
    /// </code>
    /// </example>
    public class CmsSignedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly SignedData m_signedData;
        private readonly CmsProcessable m_signedContent;
        private readonly IDictionary<string, byte[]> m_hashes;

        // Lazily constructed
        private SignerInformationStore m_signerInfoStore;

        private CmsSignedData(DerObjectIdentifier contentType, SignedData signedData, CmsProcessable signedContent,
            SignerInformationStore signerInfoStore)
        {
            m_contentInfo = new ContentInfo(contentType, signedData);
            m_signedData = signedData;
            m_signedContent = signedContent;
            m_hashes = null;
            m_signerInfoStore = signerInfoStore;
        }

        /// <summary>Create a signed data object from its encoding.</summary>
        /// <param name="sigBlock">The encoded ContentInfo.</param>
        public CmsSignedData(byte[] sigBlock)
            : this(CmsUtilities.ReadContentInfo(sigBlock))
        {
        }

        /// <summary>Create a signed data object for detached content from its encoding.</summary>
        /// <param name="signedContent">The detached content that was signed.</param>
        /// <param name="sigBlock">The encoded ContentInfo.</param>
        [Obsolete("Use 'CmsSignedData(CmsTypedData, byte[])' instead")]
        public CmsSignedData(CmsProcessable signedContent, byte[] sigBlock)
            : this(signedContent, CmsUtilities.ReadContentInfo(sigBlock))
        {
        }

        /// <summary>Create a signed data object for detached content from its encoding.</summary>
        /// <param name="signedContent">The detached content that was signed.</param>
        /// <param name="sigBlock">The encoded ContentInfo.</param>
        public CmsSignedData(CmsTypedData signedContent, byte[] sigBlock)
            : this(signedContent, CmsUtilities.ReadContentInfo(sigBlock))
        {
        }

        /// <summary>
        /// Create a signed data object for detached content, given only its digests, from its encoding.
        /// </summary>
        /// <param name="hashes">The precomputed digests of the detached content, keyed by digest algorithm OID.</param>
        /// <param name="sigBlock">The encoded ContentInfo.</param>
        public CmsSignedData(IDictionary<string, byte[]> hashes, byte[] sigBlock)
            : this(hashes, CmsUtilities.ReadContentInfo(sigBlock))
        {
        }

        /// <summary>Create a signed data object for detached content, reading the encoding from a stream.</summary>
        /// <param name="signedContent">The detached content that was signed.</param>
        /// <param name="sigData">A stream containing the encoded ContentInfo.</param>
        [Obsolete("Use 'CmsSignedData(CmsTypedData, Stream)' instead")]
        public CmsSignedData(CmsProcessable signedContent, Stream sigData)
            : this(signedContent, CmsUtilities.ReadContentInfo(sigData))
        {
        }

        /// <summary>Create a signed data object for detached content, reading the encoding from a stream.</summary>
        /// <param name="signedContent">The detached content that was signed.</param>
        /// <param name="sigData">A stream containing the encoded ContentInfo.</param>
        public CmsSignedData(CmsTypedData signedContent, Stream sigData)
            : this(signedContent, CmsUtilities.ReadContentInfo(sigData))
        {
        }

        /// <summary>Create a signed data object, reading the encoding from a stream.</summary>
        /// <param name="sigData">A stream containing the encoded ContentInfo.</param>
        public CmsSignedData(Stream sigData)
            : this(CmsUtilities.ReadContentInfo(sigData))
        {
        }

        /// <summary>Create a signed data object for detached content.</summary>
        /// <param name="signedContent">The detached content that was signed.</param>
        /// <param name="sigData">The ContentInfo carrying the signed data.</param>
        /// <exception cref="ArgumentNullException"><paramref name="sigData"/> is null.</exception>
        [Obsolete("Use 'CmsSignedData(CmsTypedData, ContentInfo)' instead")]
        public CmsSignedData(CmsProcessable signedContent, ContentInfo sigData)
        {
            m_contentInfo = sigData ?? throw new ArgumentNullException(nameof(sigData));
            m_signedData = GetSignedData(sigData);
            m_hashes = null;
            m_signedContent = signedContent;
        }

        /// <summary>Create a signed data object for detached content.</summary>
        /// <param name="signedContent">The detached content that was signed.</param>
        /// <param name="sigData">The ContentInfo carrying the signed data.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="signedContent"/> or <paramref name="sigData"/> is null.
        /// </exception>
        public CmsSignedData(CmsTypedData signedContent, ContentInfo sigData)
        {
            // Restriction follows bc-java behaviour
            if (signedContent == null)
                throw new ArgumentNullException(nameof(signedContent));

            m_contentInfo = sigData ?? throw new ArgumentNullException(nameof(sigData));
            m_signedData = GetSignedData(sigData);
            m_hashes = null;
            m_signedContent = signedContent;
        }

        /// <summary>Create a signed data object for detached content, given only its digests.</summary>
        /// <param name="hashes">The precomputed digests of the detached content, keyed by digest algorithm OID.</param>
        /// <param name="sigData">The ContentInfo carrying the signed data.</param>
        /// <exception cref="ArgumentNullException"><paramref name="sigData"/> is null.</exception>
        public CmsSignedData(IDictionary<string, byte[]> hashes, ContentInfo sigData)
        {
            m_contentInfo = sigData ?? throw new ArgumentNullException(nameof(sigData));
            m_signedData = GetSignedData(sigData);
            m_signedContent = null;
            m_hashes = hashes;
        }

        /// <summary>
        /// Create a signed data object (the content, if any, is taken from the encapsulated content info).
        /// </summary>
        /// <param name="sigData">The ContentInfo carrying the signed data.</param>
        /// <exception cref="ArgumentNullException"><paramref name="sigData"/> is null.</exception>
        public CmsSignedData(ContentInfo sigData)
        {
            m_contentInfo = sigData ?? throw new ArgumentNullException(nameof(sigData));
            m_signedData = GetSignedData(sigData);

            var encapContentInfo = m_signedData.EncapContentInfo;
            var encapContent = encapContentInfo.Content;

            if (encapContent == null)
            {
                m_signedContent = null;
            }
            else if (encapContent is Asn1OctetString octetString)
            {
                m_signedContent = new CmsProcessableByteArray(encapContentInfo.ContentType, octetString.GetOctets());
            }
            else
            {
                m_signedContent = new Pkcs7ProcessableObject(encapContentInfo.ContentType, encapContent);
            }
        }

        /// <summary>
        /// Return a copy of this <c>CmsSignedData</c> with the <c>SignedData</c> version field forced to the given
        /// value, leaving every other field unchanged.
        /// </summary>
        /// <remarks>
        /// The version is normally recomputed from the content per RFC 5652 sec. 5.1 (for example, a non-id-data
        /// eContentType implies version 3), including by <c>ReplaceSigners</c> and <c>AddDigestAlgorithm</c>. This
        /// method lets a producer pin a specific version for interop with profiles that require one - notably
        /// Microsoft Authenticode, whose signatures must carry version 1 even though their SPC_INDIRECT_DATA
        /// eContentType would otherwise compute to 3.
        /// </remarks>
        /// <param name="version">The CMSVersion value to set.</param>
        /// <returns>A new CmsSignedData carrying the supplied version.</returns>
        public CmsSignedData AsVersion(int version)
        {
            SignedData current = m_signedData;
            SignedData newContent = new SignedData(DerInteger.ValueOf(version), current.DigestAlgorithms,
                current.EncapContentInfo, current.Certificates, current.CRLs, current.SignerInfos);

            return new CmsSignedData(m_contentInfo.ContentType, newContent, m_signedContent, m_signerInfoStore);
        }

        /// <summary>Gets the underlying ContentInfo.</summary>
        public ContentInfo ContentInfo => m_contentInfo;

        /// <summary>Return a store containing the attribute certificates, if any, contained in this message.</summary>
        /// <returns>A store of attribute certificates.</returns>
        public IStore<X509V2AttributeCertificate> GetAttributeCertificates() =>
            CmsSignedHelper.GetAttributeCertificates(SignedData.Certificates);

        /// <summary>Return a store containing the public key certificates, if any, contained in this message.</summary>
        /// <returns>A store of public key certificates.</returns>
        public IStore<X509Certificate> GetCertificates() => CmsSignedHelper.GetCertificates(SignedData.Certificates);

        /// <summary>Return a store containing the CRLs, if any, contained in this message.</summary>
        /// <returns>A store of CRLs.</returns>
        public IStore<X509Crl> GetCrls() => CmsSignedHelper.GetCrls(SignedData.CRLs);

        /// <remarks>Does not preserve the original order in SignedData.DigestAlgorithms.</remarks>
        [Obsolete("Use 'GetDigestAlgorithms' instead")]
        public ISet<AlgorithmIdentifier> GetDigestAlgorithmIDs()
        {
            HashSet<AlgorithmIdentifier> result = new HashSet<AlgorithmIdentifier>();

            foreach (var entry in SignedData.DigestAlgorithms)
            {
                result.Add(AlgorithmIdentifier.GetInstance(entry));
            }

            return CollectionUtilities.ReadOnly(result);
        }

        /// <summary>Return the digest algorithms used by the signers, as listed in the signed data.</summary>
        public IEnumerable<AlgorithmIdentifier> GetDigestAlgorithms() =>
            CollectionUtilities.Select(SignedData.DigestAlgorithms, AlgorithmIdentifier.GetInstance);

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        /// <summary>Return the ASN.1 encoded representation of this object using the specified encoding.</summary>
        /// <param name="encoding">The ASN.1 encoding format to use ("BER" or "DER").</param>
        public byte[] GetEncoded(string encoding) => m_contentInfo.GetEncoded(encoding);

        /// <summary>
        /// Return a store of the other revocation information of the given format, if any, contained in this message.
        /// </summary>
        /// <param name="otherRevInfoFormat">The OID of the other revocation information format.</param>
        public IStore<Asn1Encodable> GetOtherRevInfos(DerObjectIdentifier otherRevInfoFormat) =>
            CmsSignedHelper.GetOtherRevInfos(m_signedData.CRLs, otherRevInfoFormat);

        /// <summary>Return the collection of signers that are associated with the signatures for the message.</summary>
        public SignerInformationStore GetSignerInfos()
        {
            if (m_signerInfoStore == null)
            {
                var signerInfos = new List<SignerInformation>();

                foreach (object element in SignedData.SignerInfos)
                {
                    SignerInfo signerInfo = SignerInfo.GetInstance(element);
                    DerObjectIdentifier contentType = SignedData.EncapContentInfo.ContentType;

                    if (m_hashes == null)
                    {
                        signerInfos.Add(new SignerInformation(signerInfo, contentType, SignedContent, null));
                    }
                    else if (m_hashes.TryGetValue(signerInfo.DigestAlgorithm.Algorithm.GetID(), out var hash))
                    {
                        signerInfos.Add(new SignerInformation(signerInfo, contentType, null, hash));
                    }
                    else
                    {
                        throw new InvalidOperationException();
                    }
                }

                m_signerInfoStore = new SignerInformationStore(signerInfos);
            }

            return m_signerInfoStore;
        }

        /// <summary>Whether this is a certificate management message (no content and no signers).</summary>
        public bool IsCertificateManagementMessage =>
            m_signedData.EncapContentInfo.Content == null && m_signedData.SignerInfos.Count == 0;

        /// <summary>Whether this is a detached signature (no encapsulated content, but at least one signer).</summary>
        public bool IsDetachedSignature =>
            m_signedData.EncapContentInfo.Content == null && m_signedData.SignerInfos.Count > 0;

        // TODO[api] Change return type to CmsTypedData (only when dropping CmsProcessable constructors too)
        /// <summary>Gets the signed content, or null if it is neither encapsulated nor supplied.</summary>
        public CmsProcessable SignedContent => m_signedContent;

        /// <summary>
        /// Return the <c>DerObjectIdentifier</c> associated with the encapsulated
        /// content info structure carried in the signed data.
        /// </summary>
        public DerObjectIdentifier SignedContentType => SignedData.EncapContentInfo.ContentType;

        /// <summary>Gets the underlying ASN.1 signed data.</summary>
        public SignedData SignedData => m_signedData;

        /// <summary>Return the version number for this object.</summary>
        public int Version => SignedData.Version.IntValueExact;

        /// <summary>
        /// Return a new <see cref="CmsSignedData"/> which is guaranteed to contain the passed in digest algorithm. Uses
        /// <see cref="DefaultDigestAlgorithmFinder"/> for creating the digest sets.
        /// </summary>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="digestAlgorithm">The digest algorithm to be added to the signed data.</param>
        /// <returns>A new signed data object.</returns>
        public static CmsSignedData AddDigestAlgorithm(CmsSignedData signedData, AlgorithmIdentifier digestAlgorithm) =>
            AddDigestAlgorithm(signedData, digestAlgorithm, DefaultDigestAlgorithmFinder.Instance);

        /// <summary>
        /// Return a new <see cref="CmsSignedData"/> which is guaranteed to contain the passed in digest algorithm. Uses
        /// the passed in <see cref="IDigestAlgorithmFinder"/> for creating the digest sets.
        /// </summary>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="digestAlgorithm">The digest algorithm to be added to the signed data.</param>
        /// <param name="digestAlgorithmFinder">The digest algorithm finder to generate the digest set with.</param>
        /// <returns>A new signed data object.</returns>
        public static CmsSignedData AddDigestAlgorithm(CmsSignedData signedData, AlgorithmIdentifier digestAlgorithm,
            IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            var digestAlgorithmsBuilder = new DigestAlgorithmsBuilder(digestAlgorithmFinder);
            digestAlgorithmsBuilder.AddExisting(signedData.GetDigestAlgorithms());

            // If the algorithm is already present, there is nothing to do.
            if (!digestAlgorithmsBuilder.Add(digestAlgorithm))
                return signedData;

            var oldContent = signedData.SignedData;

            Asn1Set newDigestAlgorithms = digestAlgorithmsBuilder.Build(
                useDL: !(oldContent.DigestAlgorithms is BerSet));

            var newContent = new SignedData(newDigestAlgorithms, oldContent.EncapContentInfo, oldContent.Certificates,
                oldContent.CRLs, oldContent.SignerInfos);

            return new CmsSignedData(signedData.ContentInfo.ContentType, newContent, signedData.m_signedContent,
                signedData.m_signerInfoStore);
        }

        /// <summary>
        /// Replace the <see cref="SignerInformationStore"/> associated with this object with the new one passed in,
        /// using <see cref="DefaultDigestAlgorithmFinder"/> for creating the digest sets.
        /// </summary>
        /// <remarks>
        /// You would probably only want to do this if you wanted to change the unsigned attributes associated with a
        /// signer, or perhaps delete one.
        /// </remarks>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="signerInformationStore">The new signer information store to use.</param>
        /// <returns>A new signed data object.</returns>
        public static CmsSignedData ReplaceSigners(CmsSignedData signedData,
            SignerInformationStore signerInformationStore) =>
                ReplaceSigners(signedData, signerInformationStore, DefaultDigestAlgorithmFinder.Instance);

        /// <summary>
        /// Replace the <see cref="SignerInformationStore"/> associated with this object with the new one passed in,
        /// using the passed in <see cref="IDigestAlgorithmFinder"/> for creating the digest sets.
        /// </summary>
        /// <remarks>
        /// You would probably only want to do this if you wanted to change the unsigned attributes associated with a
        /// signer, or perhaps delete one.
        /// </remarks>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="signerInformationStore">The new signer information store to use.</param>
        /// <param name="digestAlgorithmFinder">The digest algorithm finder to generate the digest set with.</param>
        /// <returns>A new signed data object.</returns>
        public static CmsSignedData ReplaceSigners(CmsSignedData signedData,
            SignerInformationStore signerInformationStore, IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            // Preserve the absent parameter format for any existing digest algorithms that are used.
            digestAlgorithmFinder = new PreserveAbsentParameters(digestAlgorithmFinder,
                signedData.GetDigestAlgorithms());

            var digestAlgorithmsBuilder = new DigestAlgorithmsBuilder(digestAlgorithmFinder);

            var signers = signerInformationStore.SignersInternal;
            var signerInfos = new List<SignerInfo>(signers.Count);

            foreach (var signerInformation in signers)
            {
                // TODO[cms] Avoid inconsistency b/w digestAlgorithms and signer digest algorithms?
                CmsUtilities.AddDigestAlgorithms(digestAlgorithmsBuilder, signerInformation);
                signerInfos.Add(signerInformation.SignerInfo);
            }

            var oldContent = signedData.SignedData;

            Asn1Set newDigestAlgorithms = digestAlgorithmsBuilder.Build(
                useDL: !(oldContent.DigestAlgorithms is BerSet));

            Asn1Set newSignerInfos = signerInfos.ToAsn1Set(useDer: false,
                useDL: !(oldContent.SignerInfos is BerSet));

            var newContent = new SignedData(newDigestAlgorithms, oldContent.EncapContentInfo, oldContent.Certificates,
                oldContent.CRLs, newSignerInfos);

            return new CmsSignedData(signedData.ContentInfo.ContentType, newContent, signedData.m_signedContent,
                signerInformationStore);
        }

        /// <summary>
        /// Replace the certificate and CRL information associated with this object with the new ones passed in.
        /// </summary>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="x509Certs">The new certificates to be used.</param>
        /// <param name="x509Crls">The new CRLs to be used.</param>
        /// <returns>A new signed data object.</returns>
        /// <exception cref="CmsException">If there is an error processing the stores.</exception>
        public static CmsSignedData ReplaceCertificatesAndCrls(CmsSignedData signedData,
            IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls)
        {
            return ReplaceCertificatesAndRevocations(signedData, x509Certs, x509Crls, null, null);
        }

        /// <summary>
        /// Replace the certificate, CRL and attribute certificate information associated with this object with the new
        /// ones passed in.
        /// </summary>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="x509Certs">The new certificates to be used.</param>
        /// <param name="x509Crls">The new CRLs to be used.</param>
        /// <param name="x509AttrCerts">The new attribute certificates to be used.</param>
        /// <returns>A new signed data object.</returns>
        /// <exception cref="CmsException">If there is an error processing the stores.</exception>
        public static CmsSignedData ReplaceCertificatesAndCrls(CmsSignedData signedData,
            IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls,
            IStore<X509V2AttributeCertificate> x509AttrCerts)
        {
            return ReplaceCertificatesAndRevocations(signedData, x509Certs, x509Crls, x509AttrCerts, null);
        }

        /// <summary>
        /// Replace the certificate, attribute certificate and revocation information (CRLs and other revocation
        /// information) associated with this object with the new ones passed in.
        /// </summary>
        /// <param name="signedData">The signed data object to be used as a base.</param>
        /// <param name="x509Certs">The new certificates to be used.</param>
        /// <param name="x509Crls">The new CRLs to be used.</param>
        /// <param name="x509AttrCerts">The new attribute certificates to be used.</param>
        /// <param name="otherRevocationInfos">The new other revocation information to be used.</param>
        /// <returns>A new signed data object.</returns>
        /// <exception cref="CmsException">If there is an error processing the stores.</exception>
        public static CmsSignedData ReplaceCertificatesAndRevocations(CmsSignedData signedData,
            IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls,
            IStore<X509V2AttributeCertificate> x509AttrCerts, IStore<OtherRevocationInfoFormat> otherRevocationInfos)
        {
            //
            // replace the certs and crls in the SignedData object
            //
            Asn1Set certSet = null;
            Asn1Set revocationSet = null;

            if (x509Certs != null || x509AttrCerts != null)
            {
                var certificates = new List<Asn1Encodable>();
                if (x509Certs != null)
                {
                    CmsUtilities.CollectCertificates(certificates, x509Certs);
                }
                if (x509AttrCerts != null)
                {
                    CmsUtilities.CollectAttributeCertificates(certificates, x509AttrCerts);
                }

                Asn1Set berSet = CmsUtilities.ToBerSet(certificates);
                if (berSet.Count > 0)
                {
                    certSet = berSet;
                }
            }

            if (x509Crls != null || otherRevocationInfos != null)
            {
                var revocations = new List<Asn1Encodable>();
                if (x509Crls != null)
                {
                    CmsUtilities.CollectCrls(revocations, x509Crls);
                }
                if (otherRevocationInfos != null)
                {
                    CmsUtilities.CollectOtherRevocationInfos(revocations, otherRevocationInfos);
                }

                Asn1Set berSet = CmsUtilities.ToBerSet(revocations);
                if (berSet.Count > 0)
                {
                    revocationSet = berSet;
                }
            }

            var oldContent = signedData.SignedData;

            var newContent = new SignedData(oldContent.DigestAlgorithms, oldContent.EncapContentInfo, certSet,
                revocationSet, oldContent.SignerInfos);

            return new CmsSignedData(signedData.ContentInfo.ContentType, newContent, signedData.m_signedContent,
                signedData.m_signerInfoStore);
        }

        private static SignedData GetSignedData(ContentInfo contentInfo) =>
            CmsUtilities.SafeGetContent(contentInfo, SignedData.GetInstance);

        private class PreserveAbsentParameters
            : IDigestAlgorithmFinder
        {
            private readonly IDigestAlgorithmFinder m_inner;
            private readonly Dictionary<DerObjectIdentifier, AlgorithmIdentifier> m_absent;

            internal PreserveAbsentParameters(IDigestAlgorithmFinder inner, IEnumerable<AlgorithmIdentifier> algIDs)
            {
                m_inner = inner ?? throw new ArgumentNullException(nameof(inner));
                m_absent = BuildAbsent(algIDs ?? throw new ArgumentNullException(nameof(algIDs)));
            }

            public AlgorithmIdentifier Find(AlgorithmIdentifier signatureAlgorithm) =>
                Preserve(m_inner.Find(signatureAlgorithm));

            public AlgorithmIdentifier Find(DerObjectIdentifier digestOid)
            {
                if (m_absent.TryGetValue(digestOid, out var result))
                    return result;

                return m_inner.Find(digestOid);
            }

            public AlgorithmIdentifier Find(string digestName) => Preserve(m_inner.Find(digestName));

            private AlgorithmIdentifier Preserve(AlgorithmIdentifier algID)
            {
                if (X509Utilities.HasAbsentParameters(algID))
                {
                    if (m_absent.TryGetValue(algID.Algorithm, out var result))
                        return result;
                }
                return algID;
            }

            private static Dictionary<DerObjectIdentifier, AlgorithmIdentifier> BuildAbsent(
                IEnumerable<AlgorithmIdentifier> algIDs)
            {
                var result = new Dictionary<DerObjectIdentifier, AlgorithmIdentifier>();
                foreach (var algID in algIDs)
                {
                    if (X509Utilities.HasAbsentParameters(algID))
                    {
                        CollectionUtilities.TryAdd(result, algID.Algorithm, algID);
                    }
                }
                return result;
            }
        }
    }
}
