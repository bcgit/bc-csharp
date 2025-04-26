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
        private readonly CmsProcessable signedContent;
        private SignedData signedData;
        private ContentInfo contentInfo;
        private SignerInformationStore signerInfoStore;
        private IDictionary<string, byte[]> m_hashes;

        private CmsSignedData(CmsSignedData c)
        {
            this.signedData = c.signedData;
            this.contentInfo = c.contentInfo;
            this.signedContent = c.signedContent;
            this.signerInfoStore = c.signerInfoStore;
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
            this.signedContent = signedContent;
            this.contentInfo = sigData;
            this.signedData = SignedData.GetInstance(contentInfo.Content);
        }

        public CmsSignedData(IDictionary<string, byte[]> hashes, ContentInfo sigData)
        {
            this.m_hashes = hashes;
            this.contentInfo = sigData;
            this.signedData = SignedData.GetInstance(contentInfo.Content);
        }

        public CmsSignedData(ContentInfo sigData)
        {
            this.contentInfo = sigData;
            this.signedData = SignedData.GetInstance(contentInfo.Content);

            var encapContentInfo = signedData.EncapContentInfo;
            var encapContent = encapContentInfo.Content;

            if (encapContent != null)
            {
                if (encapContent is Asn1OctetString octetString)
                {
                    this.signedContent = new CmsProcessableByteArray(octetString.GetOctets());
                }
                else
                {
                    this.signedContent = new Pkcs7ProcessableObject(encapContentInfo.ContentType, encapContent);
                }
            }
        }

        /// <summary>Return the version number for this object.</summary>
        public int Version
        {
            get { return signedData.Version.IntValueExact; }
        }

        /**
         * return the collection of signers that are associated with the
         * signatures for the message.
         */
        public SignerInformationStore GetSignerInfos()
        {
            if (signerInfoStore == null)
            {
                var signerInfos = new List<SignerInformation>();
                Asn1Set s = signedData.SignerInfos;

                foreach (object obj in s)
                {
                    SignerInfo info = SignerInfo.GetInstance(obj);
                    DerObjectIdentifier contentType = signedData.EncapContentInfo.ContentType;

                    if (m_hashes == null)
                    {
                        signerInfos.Add(new SignerInformation(info, contentType, signedContent, null));
                    }
                    else if (m_hashes.TryGetValue(info.DigestAlgorithm.Algorithm.Id, out var hash))
                    {
                        signerInfos.Add(new SignerInformation(info, contentType, null, hash));
                    }
                    else
                    {
                        throw new InvalidOperationException();
                    }
                }

                signerInfoStore = new SignerInformationStore(signerInfos);
            }

            return signerInfoStore;
        }

        /**
         * return a X509Store containing the attribute certificates, if any, contained
         * in this message.
         *
         * @param type type of store to create
         * @return a store of attribute certificates
         * @exception NoSuchStoreException if the store type isn't available.
         * @exception CmsException if a general exception prevents creation of the X509Store
         */
        public IStore<X509V2AttributeCertificate> GetAttributeCertificates()
        {
            return CmsSignedHelper.GetAttributeCertificates(signedData.Certificates);
        }

        /**
         * return a X509Store containing the public key certificates, if any, contained in this message.
         *
         * @return a store of public key certificates
         * @exception NoSuchStoreException if the store type isn't available.
         * @exception CmsException if a general exception prevents creation of the X509Store
         */
        public IStore<X509Certificate> GetCertificates()
        {
            return CmsSignedHelper.GetCertificates(signedData.Certificates);
        }

        /**
         * return a X509Store containing CRLs, if any, contained in this message.
         *
         * @return a store of CRLs
         * @exception NoSuchStoreException if the store type isn't available.
         * @exception CmsException if a general exception prevents creation of the X509Store
         */
        public IStore<X509Crl> GetCrls()
        {
            return CmsSignedHelper.GetCrls(signedData.CRLs);
        }

        public IStore<Asn1Encodable> GetOtherRevInfos(DerObjectIdentifier otherRevInfoFormat)
        {
            return CmsSignedHelper.GetOtherRevInfos(signedData.CRLs, otherRevInfoFormat);
        }

        /**
         * Return the digest algorithm identifiers for the SignedData object
         *
         * @return the set of digest algorithm identifiers
         */
        public ISet<AlgorithmIdentifier> GetDigestAlgorithmIDs()
        {
            var digestAlgorithms = signedData.DigestAlgorithms;

            HashSet<AlgorithmIdentifier> result = new HashSet<AlgorithmIdentifier>();

            foreach (var entry in digestAlgorithms)
            {
                result.Add(AlgorithmIdentifier.GetInstance(entry));
            }

            return CollectionUtilities.ReadOnly(result);
        }

        /// <summary>
        /// Return the <c>DerObjectIdentifier</c> associated with the encapsulated
        /// content info structure carried in the signed data.
        /// </summary>
        public DerObjectIdentifier SignedContentType
        {
            get { return signedData.EncapContentInfo.ContentType; }
        }

        public CmsProcessable SignedContent
        {
            get { return signedContent; }
        }

        /**
         * return the ContentInfo
         */
        public ContentInfo ContentInfo
        {
            get { return contentInfo; }
        }

        /**
         * return the ASN.1 encoded representation of this object.
         */
        public byte[] GetEncoded()
        {
            return contentInfo.GetEncoded();
        }

        /**
         * return the ASN.1 encoded representation of this object using the specified encoding.
         *
         * @param encoding the ASN.1 encoding format to use ("BER" or "DER").
         */
        public byte[] GetEncoded(string encoding)
        {
            return contentInfo.GetEncoded(encoding);
        }

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
            ISet<AlgorithmIdentifier> digestAlgorithms = signedData.GetDigestAlgorithmIDs();
            AlgorithmIdentifier digestAlg = CmsSignedHelper.FixDigestAlgID(digestAlgorithm, digestAlgorithmFinder);

            //
            // if the algorithm is already present there is no need to add it.
            //
            if (digestAlgorithms.Contains(digestAlg))
                return signedData;

            //
            // copy
            //
            CmsSignedData cms = new CmsSignedData(signedData);

            //
            // build up the new set
            //
            HashSet<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();

            foreach (var entry in digestAlgs)
            {
                digestAlgs.Add(CmsSignedHelper.FixDigestAlgID(entry, digestAlgorithmFinder));
            }
            digestAlgs.Add(digestAlg);

            Asn1Set digests = CmsUtilities.ConvertToDLSet(digestAlgs);
            Asn1Sequence sD = (Asn1Sequence)signedData.signedData.ToAsn1Object();

            //
            // signers are the last item in the sequence.
            //
            Asn1EncodableVector vec = new Asn1EncodableVector(sD.Count);
            vec.Add(sD[0]); // version
            vec.Add(digests);

            for (int i = 2; i != sD.Count; i++)
            {
                vec.Add(sD[i]);
            }

            cms.signedData = SignedData.GetInstance(new BerSequence(vec));

            //
            // replace the contentInfo with the new one
            //
            cms.contentInfo = new ContentInfo(cms.contentInfo.ContentType, cms.signedData);

            return cms;
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
            // keep ourselves compatible with what was there before - issue with
            // NULL appearing and disappearing in AlgorithmIdentifier parameters.
            digestAlgorithmFinder = new PreserveAbsentParameters(digestAlgorithmFinder,
                signedData.EnumerateDigestAlgorithmIDs());

            //
            // copy
            //
            CmsSignedData cms = new CmsSignedData(signedData);

            //
            // replace the store
            //
            cms.signerInfoStore = signerInformationStore;

            //
            // replace the signers in the SignedData object
            //
            HashSet<AlgorithmIdentifier> digestAlgs = new HashSet<AlgorithmIdentifier>();

            var signers = signerInformationStore.GetSigners();
            Asn1EncodableVector vec = new Asn1EncodableVector(signers.Count);

            foreach (var signer in signers)
            {
                CmsUtilities.AddDigestAlgs(digestAlgs, signer, digestAlgorithmFinder);
                vec.Add(signer.ToSignerInfo());
            }

            Asn1Set digestSet = CmsUtilities.ConvertToDLSet(digestAlgs);
            Asn1Set signerSet = DLSet.FromVector(vec);
            Asn1Sequence sD = (Asn1Sequence)signedData.signedData.ToAsn1Object();

            //
            // signers are the last item in the sequence.
            //
            vec = new Asn1EncodableVector(sD.Count);
            vec.Add(sD[0]); // version
            vec.Add(digestSet);

            for (int i = 2; i != sD.Count - 1; i++)
            {
                vec.Add(sD[i]);
            }

            vec.Add(signerSet);

            cms.signedData = SignedData.GetInstance(new BerSequence(vec));

            //
            // replace the contentInfo with the new one
            //
            cms.contentInfo = new ContentInfo(cms.contentInfo.ContentType, cms.signedData);

            return cms;
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
            // copy
            //
            CmsSignedData cms = new CmsSignedData(signedData);

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

                Asn1Set berSet = CmsUtilities.CreateBerSetFromList(certificates);
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

                Asn1Set berSet = CmsUtilities.CreateBerSetFromList(revocations);
                if (berSet.Count > 0)
                {
                    revocationSet = berSet;
                }
            }

            //
            // replace the CMS structure.
            //
            SignedData old = signedData.signedData;
            cms.signedData = new SignedData(
                old.DigestAlgorithms,
                old.EncapContentInfo,
                certSet,
                revocationSet,
                old.SignerInfos);

            //
            // replace the contentInfo with the new one
            //
            cms.contentInfo = new ContentInfo(cms.contentInfo.ContentType, cms.signedData);

            return cms;
        }

        internal IEnumerable<AlgorithmIdentifier> EnumerateDigestAlgorithmIDs()
        {
            foreach (var entry in signedData.DigestAlgorithms)
            {
                yield return AlgorithmIdentifier.GetInstance(entry);
            }
        }

        private class PreserveAbsentParameters
            : IDigestAlgorithmFinder
        {
            private readonly IDigestAlgorithmFinder m_inner;
            private readonly Dictionary<DerObjectIdentifier, AlgorithmIdentifier> m_existing;

            internal PreserveAbsentParameters(IDigestAlgorithmFinder inner,
                IEnumerable<AlgorithmIdentifier> existingAlgIDs)
            {
                m_inner = inner ?? throw new ArgumentNullException(nameof(inner));
                m_existing = BuildExisting(existingAlgIDs ?? throw new ArgumentNullException(nameof(existingAlgIDs)));
            }

            public AlgorithmIdentifier Find(AlgorithmIdentifier signatureAlgorithm) =>
                Preserve(m_inner.Find(signatureAlgorithm));

            public AlgorithmIdentifier Find(DerObjectIdentifier digestOid) =>
                m_existing.TryGetValue(digestOid, out var result) ? result : m_inner.Find(digestOid);

            public AlgorithmIdentifier Find(string digestName) => Preserve(m_inner.Find(digestName));

            private AlgorithmIdentifier Preserve(AlgorithmIdentifier algID)
            {
                if (X509Utilities.HasAbsentParameters(algID) &&
                    m_existing.TryGetValue(algID.Algorithm, out var result))
                {
                    return result;
                }

                return algID;
            }

            private static Dictionary<DerObjectIdentifier, AlgorithmIdentifier> BuildExisting(
                IEnumerable<AlgorithmIdentifier> existingAlgIDs)
            {
                var result = new Dictionary<DerObjectIdentifier, AlgorithmIdentifier>();
                foreach (var existingAlgID in existingAlgIDs)
                {
                    CollectionUtilities.TryAdd(result, existingAlgID.Algorithm, existingAlgID);
                }
                return result;
            }
        }
    }
}
