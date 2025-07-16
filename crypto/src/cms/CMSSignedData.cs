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
    /**
     * general class for handling a pkcs7-signature message.
     *
     * A simple example of usage - note, in the example below the validity of
     * the certificate isn't verified, just the fact that one of the certs
     * matches the given signer...
     *
     * <pre>
     *  IX509Store              certs = s.GetCertificates();
     *  SignerInformationStore  signers = s.GetSignerInfos();
     *
     *  foreach (SignerInformation signer in signers.GetSigners())
     *  {
     *      ArrayList       certList = new ArrayList(certs.GetMatches(signer.SignerID));
     *      X509Certificate cert = (X509Certificate) certList[0];
     *
     *      if (signer.Verify(cert.GetPublicKey()))
     *      {
     *          verified++;
     *      }
     *  }
     * </pre>
     */
    public class CmsSignedData
    {
        private readonly ContentInfo m_contentInfo;
        private readonly SignedData m_signedData;
        private readonly CmsProcessable m_signedContent;
        private readonly IDictionary<string, byte[]> m_hashes;

        // Lazily constructed
        private SignerInformationStore m_signerInfoStore;

        private CmsSignedData(CmsSignedData c)
        {
            m_contentInfo = c.m_contentInfo;
            m_signedData = c.m_signedData;
            m_signedContent = c.m_signedContent;
            m_hashes = null; // TODO[cms] Check whether we should be (deep-)copying these
            m_signerInfoStore = c.m_signerInfoStore;
        }

        private CmsSignedData(DerObjectIdentifier contentType, SignedData signedData, CmsProcessable signedContent,
            SignerInformationStore signerInfoStore)
        {
            m_contentInfo = new ContentInfo(contentType, signedData);
            m_signedData = signedData;
            m_signedContent = signedContent;
            m_hashes = null;
            m_signerInfoStore = signerInfoStore;
        }

        public CmsSignedData(byte[] sigBlock)
            : this(CmsUtilities.ReadContentInfo(new MemoryStream(sigBlock, false)))
        {
        }

        public CmsSignedData(CmsProcessable signedContent, byte[] sigBlock)
            : this(signedContent, CmsUtilities.ReadContentInfo(new MemoryStream(sigBlock, false)))
        {
        }

        /**
         * Content with detached signature, digests precomputed
         *
         * @param hashes a map of precomputed digests for content indexed by name of hash.
         * @param sigBlock the signature object.
         */
        public CmsSignedData(IDictionary<string, byte[]> hashes, byte[] sigBlock)
            : this(hashes, CmsUtilities.ReadContentInfo(sigBlock))
        {
        }

        /**
         * base constructor - content with detached signature.
         *
         * @param signedContent the content that was signed.
         * @param sigData the signature object.
         */
        public CmsSignedData(CmsProcessable signedContent, Stream sigData)
            : this(signedContent, CmsUtilities.ReadContentInfo(sigData))
        {
        }

        /**
         * base constructor - with encapsulated content
         */
        public CmsSignedData(Stream sigData)
            : this(CmsUtilities.ReadContentInfo(sigData))
        {
        }

        public CmsSignedData(CmsProcessable signedContent, ContentInfo sigData)
        {
            m_contentInfo = sigData;
            m_signedData = SignedData.GetInstance(sigData.Content);
            m_signedContent = signedContent;
        }

        public CmsSignedData(IDictionary<string, byte[]> hashes, ContentInfo sigData)
        {
            m_contentInfo = sigData;
            m_signedData = SignedData.GetInstance(sigData.Content);
            m_signedContent = null;
            m_hashes = hashes;
        }

        public CmsSignedData(ContentInfo sigData)
        {
            m_contentInfo = sigData;
            m_signedData = SignedData.GetInstance(sigData.Content);

            var encapContentInfo = m_signedData.EncapContentInfo;
            var encapContent = encapContentInfo.Content;

            if (encapContent != null)
            {
                if (encapContent is Asn1OctetString octetString)
                {
                    m_signedContent = new CmsProcessableByteArray(octetString.GetOctets());
                }
                else
                {
                    m_signedContent = new Pkcs7ProcessableObject(encapContentInfo.ContentType, encapContent);
                }
            }
        }

        /**
         * return the ContentInfo
         */
        public ContentInfo ContentInfo => m_contentInfo;

        /**
         * return a X509Store containing the attribute certificates, if any, contained
         * in this message.
         *
         * @param type type of store to create
         * @return a store of attribute certificates
         * @exception NoSuchStoreException if the store type isn't available.
         * @exception CmsException if a general exception prevents creation of the X509Store
         */
        public IStore<X509V2AttributeCertificate> GetAttributeCertificates() =>
            CmsSignedHelper.GetAttributeCertificates(SignedData.Certificates);

        /**
         * return a X509Store containing the public key certificates, if any, contained in this message.
         *
         * @return a store of public key certificates
         * @exception NoSuchStoreException if the store type isn't available.
         * @exception CmsException if a general exception prevents creation of the X509Store
         */
        public IStore<X509Certificate> GetCertificates() => CmsSignedHelper.GetCertificates(SignedData.Certificates);

        /**
         * return a X509Store containing CRLs, if any, contained in this message.
         *
         * @return a store of CRLs
         * @exception NoSuchStoreException if the store type isn't available.
         * @exception CmsException if a general exception prevents creation of the X509Store
         */
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

        public IEnumerable<AlgorithmIdentifier> GetDigestAlgorithms() =>
            CollectionUtilities.Select(SignedData.DigestAlgorithms, AlgorithmIdentifier.GetInstance);

        /**
         * return the ASN.1 encoded representation of this object.
         */
        public byte[] GetEncoded() => m_contentInfo.GetEncoded();

        /**
         * return the ASN.1 encoded representation of this object using the specified encoding.
         *
         * @param encoding the ASN.1 encoding format to use ("BER" or "DER").
         */
        public byte[] GetEncoded(string encoding) => m_contentInfo.GetEncoded(encoding);

        public IStore<Asn1Encodable> GetOtherRevInfos(DerObjectIdentifier otherRevInfoFormat) =>
            CmsSignedHelper.GetOtherRevInfos(m_signedData.CRLs, otherRevInfoFormat);

        /**
         * return the collection of signers that are associated with the
         * signatures for the message.
         */
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

        public bool IsCertificateManagementMessage =>
            m_signedData.EncapContentInfo.Content == null && m_signedData.SignerInfos.Count == 0;

        public bool IsDetachedSignature =>
            m_signedData.EncapContentInfo.Content == null && m_signedData.SignerInfos.Count > 0;

        public CmsProcessable SignedContent => m_signedContent;

        /// <summary>
        /// Return the <c>DerObjectIdentifier</c> associated with the encapsulated
        /// content info structure carried in the signed data.
        /// </summary>
        public DerObjectIdentifier SignedContentType => SignedData.EncapContentInfo.ContentType;

        public SignedData SignedData => m_signedData;

        /// <summary>Return the version number for this object.</summary>
        public int Version => SignedData.Version.IntValueExact;

        /**
         * Return a new CMSSignedData which guarantees to have the passed in digestAlgorithm
         * in it. Uses the DefaultDigestAlgorithmFinder for creating the digest sets.
         *
         * @param signedData      the signed data object to be used as a base.
         * @param digestAlgorithm the digest algorithm to be added to the signed data.
         * @return a new signed data object.
         */
        public static CmsSignedData AddDigestAlgorithm(CmsSignedData signedData, AlgorithmIdentifier digestAlgorithm) =>
            AddDigestAlgorithm(signedData, digestAlgorithm, DefaultDigestAlgorithmFinder.Instance);

        /**
         * Return a new CMSSignedData which guarantees to have the passed in digestAlgorithm
         * in it. Uses the passed in IDigestAlgorithmFinder for creating the digest sets.
         *
         * @param signedData      the signed data object to be used as a base.
         * @param digestAlgorithm the digest algorithm to be added to the signed data.
         * @param digestAlgorithmFinder the digest algorithm finder to generate the digest set with.
         * @return a new signed data object.
         */
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

        /**
         * Replace the SignerInformation store associated with this CMSSignedData object with the new one passed in
         * using the DefaultDigestAlgorithmFinder for creating the digest sets. You would probably only want
         * to do this if you wanted to change the unsigned attributes associated with a signer, or perhaps delete one.
         *
         * @param signedData             the signed data object to be used as a base.
         * @param signerInformationStore the new signer information store to use.
         * @return a new signed data object.
         */
        public static CmsSignedData ReplaceSigners(CmsSignedData signedData,
            SignerInformationStore signerInformationStore) =>
                ReplaceSigners(signedData, signerInformationStore, DefaultDigestAlgorithmFinder.Instance);

        /**
         * Replace the SignerInformation store associated with this CMSSignedData object with the new one passed in
         * using the passed in IDigestAlgorithmFinder for creating the digest sets. You would probably only
         * want to do this if you wanted to change the unsigned attributes associated with a signer, or perhaps delete
         * one.
         *
         * @param signedData             the signed data object to be used as a base.
         * @param signerInformationStore the new signer information store to use.
         * @param digestAlgorithmFinder the digest algorithm finder to generate the digest set with.
         * @return a new signed data object.
         */
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

        /**
         * Replace the certificate and CRL information associated with this
         * CmsSignedData object with the new one passed in.
         *
         * @param signedData the signed data object to be used as a base.
         * @param x509Certs the new certificates to be used.
         * @param x509Crls the new CRLs to be used.
         * @return a new signed data object.
         * @exception CmsException if there is an error processing the stores
         */
        public static CmsSignedData ReplaceCertificatesAndCrls(CmsSignedData signedData,
            IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls)
        {
            return ReplaceCertificatesAndRevocations(signedData, x509Certs, x509Crls, null, null);
        }

        public static CmsSignedData ReplaceCertificatesAndCrls(CmsSignedData signedData,
            IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls,
            IStore<X509V2AttributeCertificate> x509AttrCerts)
        {
            return ReplaceCertificatesAndRevocations(signedData, x509Certs, x509Crls, x509AttrCerts, null);
        }

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

            var content = new SignedData(oldContent.DigestAlgorithms, oldContent.EncapContentInfo, certSet,
                revocationSet, oldContent.SignerInfos);

            return new CmsSignedData(signedData.ContentInfo.ContentType, content, signedData.m_signedContent,
                signedData.m_signerInfoStore);
        }

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
