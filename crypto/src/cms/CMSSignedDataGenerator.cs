using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /**
     * general class for generating a pkcs7-signature message.
     * <p>
     * A simple example of usage.
     *
     * <pre>
     *      IX509Store certs...
     *      IX509Store crls...
     *      CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
     *
     *      gen.AddSigner(privKey, cert, CmsSignedGenerator.DigestSha1);
     *      gen.AddCertificates(certs);
     *      gen.AddCrls(crls);
     *
     *      CmsSignedData data = gen.Generate(content);
     * </pre>
	 * </p>
     */
    public class CmsSignedDataGenerator
        : CmsSignedGenerator
    {
        private readonly IList<SignerInf> signerInfs = new List<SignerInf>();

        internal bool _useDefiniteLength = false;

        private class SignerInf
        {
            private readonly CmsSignedGenerator m_outer;

            private readonly ISignatureFactory m_signatureFactory;
            private readonly SignerIdentifier m_signerID;
            private readonly AlgorithmIdentifier m_digAlgID;
            private readonly DerObjectIdentifier m_sigAlgOid;
            private readonly CmsAttributeTableGenerator m_sAttrGen;
            private readonly CmsAttributeTableGenerator m_unsAttrGen;
            private readonly Asn1.Cms.AttributeTable m_baseSignedTable;

            internal SignerInf(
                CmsSignedGenerator outer,
                AsymmetricKeyParameter key,
                SecureRandom random,
                SignerIdentifier signerID,
                DerObjectIdentifier digAlgOid,
                DerObjectIdentifier sigAlgOid,
                CmsAttributeTableGenerator sAttrGen,
                CmsAttributeTableGenerator unsAttrGen,
                Asn1.Cms.AttributeTable baseSignedTable)
            {
                ISignatureFactory signatureFactory;
                if (EdECObjectIdentifiers.id_Ed25519.Equals(sigAlgOid))
                {
                    if (!NistObjectIdentifiers.IdSha512.Equals(digAlgOid))
                        throw new CmsException("Ed25519 signature used with unsupported digest algorithm");

                    var sigAlgID = new AlgorithmIdentifier(sigAlgOid);

                    signatureFactory = new Asn1SignatureFactory(sigAlgID, key, random);
                }
                //else if (EdECObjectIdentifiers.id_Ed448.Equals(sigAlgOid))
                //{
                //    if (sAttrGen == null)
                //    {
                //        if (!NistObjectIdentifiers.IdShake256.Equals(digAlgOid))
                //            throw new CmsException("Ed448 signature used with unsupported digest algorithm");
                //    }
                //    else
                //    {
                //        // NOTE: We'd need a complete AlgorithmIdentifier ('digAlgID') instead of only 'digAlgOid'
                //        throw new ArgumentException("Ed448 cannot be used with this constructor and signed attributes");
                //    }

                //    var sigAlgID = new AlgorithmIdentifier(sigAlgOid);

                //    signatureFactory = new Asn1SignatureFactory(sigAlgID, key, random);
                //}
                else if (MLDsaParameters.ByOid.TryGetValue(sigAlgOid, out MLDsaParameters mlDsaParameters))
                {
                    if (mlDsaParameters.IsPreHash)
                        throw new CmsException($"{mlDsaParameters} prehash signature is not supported");

                    // TODO Other digests may be acceptable; keep a list and check against it

                    if (!NistObjectIdentifiers.IdSha512.Equals(digAlgOid))
                        throw new CmsException($"{mlDsaParameters} signature used with unsupported digest algorithm");

                    var sigAlgID = new AlgorithmIdentifier(sigAlgOid);

                    signatureFactory = new Asn1SignatureFactory(sigAlgID, key, random);
                }
                else if (SlhDsaParameters.ByOid.TryGetValue(sigAlgOid, out SlhDsaParameters slhDsaParameters))
                {
                    if (slhDsaParameters.IsPreHash)
                        throw new CmsException($"{slhDsaParameters} prehash signature is not supported");

                    // TODO Other digests may be acceptable; keep a list and check against it

                    var defaultDigAlgOid = CmsSignedHelper.GetSlhDsaDigestOid(sigAlgOid);
                    if (!defaultDigAlgOid.Equals(digAlgOid))
                        throw new CmsException($"{slhDsaParameters} signature used with unsupported digest algorithm");

                    var sigAlgID = new AlgorithmIdentifier(sigAlgOid);

                    signatureFactory = new Asn1SignatureFactory(sigAlgID, key, random);
                }
                else
                {
                    string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                    string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(sigAlgOid);

                    signatureFactory = new Asn1SignatureFactory(signatureName, key, random);
                }

                m_outer = outer;
                m_signatureFactory = signatureFactory;
                m_signerID = signerID;
                // TODO Configure an IDigestAlgorithmFinder
                m_digAlgID = DefaultDigestAlgorithmFinder.Instance.Find(digAlgOid);
                m_sigAlgOid = sigAlgOid;
                m_sAttrGen = sAttrGen;
                m_unsAttrGen = unsAttrGen;
                m_baseSignedTable = baseSignedTable;
            }

            internal SignerInf(
                CmsSignedGenerator outer,
                ISignatureFactory signatureFactory,
                SignerIdentifier signerID,
                CmsAttributeTableGenerator sAttrGen,
                CmsAttributeTableGenerator unsAttrGen,
                Asn1.Cms.AttributeTable baseSignedTable)
            {
                var sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;
                var sigAlgOid = sigAlgID.Algorithm;
                var sigAlgParams = sigAlgID.Parameters;

                AlgorithmIdentifier digAlgID;
                if (EdECObjectIdentifiers.id_Ed25519.Equals(sigAlgOid))
                {
                    if (sigAlgParams != null)
                        throw new CmsException("Ed25519 signature cannot specify algorithm parameters");

                    digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, null);
                }
                //else if (EdECObjectIdentifiers.id_Ed448.Equals(sigAlgOid))
                //{
                //    if (sigAlgParams != null)
                //        throw new CmsException("Ed448 signature cannot specify algorithm parameters");

                //    if (sAttrGen == null)
                //    {
                //        digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);
                //    }
                //    else
                //    {
                //        digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256Len, new DerInteger(512));
                //    }
                //}
                else if (MLDsaParameters.ByOid.TryGetValue(sigAlgOid, out MLDsaParameters mlDsaParameters))
                {
                    if (mlDsaParameters.IsPreHash)
                        throw new CmsException($"{mlDsaParameters} prehash signature is not supported");

                    if (sigAlgParams != null)
                        throw new CmsException($"{mlDsaParameters} signature cannot specify algorithm parameters");

                    // TODO Other digest might be supported; allow customization
                    digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, null);
                }
                else if (SlhDsaParameters.ByOid.TryGetValue(sigAlgOid, out SlhDsaParameters slhDsaParameters))
                {
                    if (slhDsaParameters.IsPreHash)
                        throw new CmsException($"{slhDsaParameters} prehash signature is not supported");

                    if (sigAlgParams != null)
                        throw new CmsException($"{slhDsaParameters} signature cannot specify algorithm parameters");

                    // TODO Other digest might be supported; allow customization
                    var defaultDigAlgOid = CmsSignedHelper.GetSlhDsaDigestOid(sigAlgOid);
                    digAlgID = new AlgorithmIdentifier(defaultDigAlgOid, null);
                }
                else
                {
                    // TODO Configure an IDigestAlgorithmFinder
                    digAlgID = DefaultDigestAlgorithmFinder.Instance.Find(sigAlgID);
                }

                m_outer = outer;
                m_signatureFactory = signatureFactory;
                m_signerID = signerID;
                m_digAlgID = digAlgID;
                m_sigAlgOid = sigAlgOid;
                m_sAttrGen = sAttrGen;
                m_unsAttrGen = unsAttrGen;
                m_baseSignedTable = baseSignedTable;
            }

            internal SignerInfo ToSignerInfo(DerObjectIdentifier contentType, CmsProcessable content)
            {
                AlgorithmIdentifier digAlgID = m_digAlgID;
                DerObjectIdentifier digAlgOid = digAlgID.Algorithm;

                if (!m_outer.m_digests.TryGetValue(digAlgOid, out var hash))
                {
                    IDigest dig = DigestUtilities.GetDigest(digAlgOid);
                    if (content != null)
                    {
                        using (var stream = new DigestSink(dig))
                        {
                            content.Write(stream);
                        }
                    }
                    hash = DigestUtilities.DoFinal(dig);
                    m_outer.m_digests.Add(digAlgOid, hash);
                }

                Asn1Set signedAttr = null;

                IStreamCalculator<IBlockResult> calculator = m_signatureFactory.CreateCalculator();
                using (Stream sigStr = calculator.Stream)
                {
                    if (m_sAttrGen != null)
                    {
                        var parameters = m_outer.GetBaseParameters(contentType, digAlgID, hash);

                        Asn1.Cms.AttributeTable signed = m_sAttrGen.GetAttributes(
                            CollectionUtilities.ReadOnly(parameters));

                        if (contentType == null) //counter signature
                        {
                            signed = signed?.Remove(CmsAttributes.ContentType);
                        }

                        // TODO Validate proposed signed attributes

                        signedAttr = m_outer.GetAttributeSet(signed);

                        // sig must be composed from the DER encoding.
                        signedAttr.EncodeTo(sigStr, Asn1Encodable.Der);
                    }
                    else if (content != null)
                    {
                        // TODO Use raw signature of the hash value instead (when sig alg uses external digest)
                        content.Write(sigStr);
                    }
                }

                byte[] sigBytes = calculator.GetResult().Collect();

                Asn1Set unsignedAttr = null;
                if (m_unsAttrGen != null)
                {
                    var baseParameters = m_outer.GetBaseParameters(contentType, digAlgID, hash);
                    baseParameters[CmsAttributeTableParameter.Signature] = sigBytes.Clone();

                    Asn1.Cms.AttributeTable unsigned = m_unsAttrGen.GetAttributes(
                        CollectionUtilities.ReadOnly(baseParameters));

                    // TODO Validate proposed unsigned attributes

                    unsignedAttr = m_outer.GetAttributeSet(unsigned);
                }

                AlgorithmIdentifier sigAlgID;
                if (EdECObjectIdentifiers.id_Ed25519.Equals(m_sigAlgOid))
                {
                    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid, null);
                }
                //else if (EdECObjectIdentifiers.id_Ed448.Equals(m_sigAlgOid))
                //{
                //    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid, null);
                //}
                else if (MLDsaParameters.ByOid.TryGetValue(m_sigAlgOid, out MLDsaParameters mlDsaParameters))
                {
                    Debug.Assert(!mlDsaParameters.IsPreHash);
                    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid, null);
                }
                else if (SlhDsaParameters.ByOid.TryGetValue(m_sigAlgOid, out SlhDsaParameters slhDsaParameters))
                {
                    Debug.Assert(!slhDsaParameters.IsPreHash);
                    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid, null);
                }
                else
                {
                    string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                    string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(m_sigAlgOid);

                    // TODO[RSAPSS] Need the ability to specify non-default parameters
                    Asn1Encodable sigAlgParams = SignerUtilities.GetDefaultX509Parameters(signatureName);
                    sigAlgID = CmsSignedHelper.GetSigAlgID(m_sigAlgOid, sigAlgParams);
                }

                return new SignerInfo(m_signerID, digAlgID, signedAttr, sigAlgID, new DerOctetString(sigBytes),
                    unsignedAttr);
            }
        }

        public CmsSignedDataGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsSignedDataGenerator(SecureRandom random)
            : base(random)
        {
        }

        /**
         * add a signer - no attributes other than the default ones will be
         * provided here.
         *
         * @param key signing key to use
         * @param cert certificate containing corresponding public key
         * @param digestOID digest algorithm OID
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID) =>
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID);

        /**
         * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones
         * will be provided here.
         *
         * @param key signing key to use
         * @param cert certificate containing corresponding public key
         * @param encryptionOID digest encryption algorithm OID
         * @param digestOID digest algorithm OID
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID,
            string digestOID)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(), null, null);
        }

        /**
         * add a signer - no attributes other than the default ones will be
         * provided here.
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID) =>
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID);

        /**
         * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
         * provided here.
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID,
            string digestOID)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(), null, null);
        }

        /**
         * add a signer with extra signed/unsigned attributes.
         *
         * @param key signing key to use
         * @param cert certificate containing corresponding public key
         * @param digestOID digest algorithm OID
         * @param signedAttr table of attributes to be included in signature
         * @param unsignedAttr table of attributes to be included as unsigned
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttr, unsignedAttr);
        }

        /**
         * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes.
         *
         * @param key signing key to use
         * @param cert certificate containing corresponding public key
         * @param encryptionOID digest encryption algorithm OID
         * @param digestOID digest algorithm OID
         * @param signedAttr table of attributes to be included in signature
         * @param unsignedAttr table of attributes to be included as unsigned
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID,
            string digestOID, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
        }

        /**
         * add a signer with extra signed/unsigned attributes.
         *
         * @param key signing key to use
         * @param subjectKeyID subjectKeyID of corresponding public key
         * @param digestOID digest algorithm OID
         * @param signedAttr table of attributes to be included in signature
         * @param unsignedAttr table of attributes to be included as unsigned
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttr, unsignedAttr);
        }

        /**
         * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes.
         *
         * @param key signing key to use
         * @param subjectKeyID subjectKeyID of corresponding public key
         * @param encryptionOID digest encryption algorithm OID
         * @param digestOID digest algorithm OID
         * @param signedAttr table of attributes to be included in signature
         * @param unsignedAttr table of attributes to be included as unsigned
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID,
            string digestOID, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
        }

        /**
         * add a signer with extra signed/unsigned attributes based on generators.
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID,
            CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttrGen, unsignedAttrGen);
        }

        /**
         * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes based on generators.
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID,
            string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), signedAttrGen, unsignedAttrGen, null);
        }

        /**
         * add a signer with extra signed/unsigned attributes based on generators.
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID,
            CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttrGen, unsignedAttrGen);
        }

        /**
         * add a signer, including digest encryption algorithm, with extra signed/unsigned attributes based on generators.
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID,
            string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), signedAttrGen, unsignedAttrGen, null);
        }

        public void AddSignerInfoGenerator(SignerInfoGenerator signerInfoGenerator)
        {
            signerInfs.Add(
                new SignerInf(this, signerInfoGenerator.SignatureFactory, signerInfoGenerator.SignerID,
                    signerInfoGenerator.SignedAttributeTableGenerator,
                    signerInfoGenerator.UnsignedAttributeTableGenerator, baseSignedTable: null));
        }

        private void DoAddSigner(AsymmetricKeyParameter privateKey, SignerIdentifier signerIdentifier,
            DerObjectIdentifier encryptionOid, DerObjectIdentifier digestOid, CmsAttributeTableGenerator signedAttrGen,
            CmsAttributeTableGenerator unsignedAttrGen, Asn1.Cms.AttributeTable baseSignedTable)
        {
            signerInfs.Add(new SignerInf(this, privateKey, m_random, signerIdentifier, digestOid, encryptionOid,
                signedAttrGen, unsignedAttrGen, baseSignedTable));
        }

        /**
         * generate a signed object that for a CMS Signed Data object
         */
        public CmsSignedData Generate(CmsProcessable content) => Generate(content, encapsulate: false);

        /**
         * generate a signed object that for a CMS Signed Data
         * object - if encapsulate is true a copy
         * of the message will be included in the signature with the
         * default content type "data".
         */
        public CmsSignedData Generate(CmsProcessable content, bool encapsulate) =>
            Generate(signedContentType: Data, content, encapsulate);

        /**
         * generate a signed object that for a CMS Signed Data
         * object  - if encapsulate is true a copy
         * of the message will be included in the signature. The content type
         * is set according to the OID represented by the string signedContentType.
         */
        public CmsSignedData Generate(
            string signedContentType,
            // FIXME Avoid accessing more than once to support CmsProcessableInputStream
            CmsProcessable content,
            bool encapsulate)
        {
            // TODO Configure an IDigestAlgorithmFinder
            var digestAlgorithmsBuilder = new DigestAlgorithmsBuilder(DefaultDigestAlgorithmFinder.Instance);

            Asn1EncodableVector signerInfos = new Asn1EncodableVector(_signers.Count + signerInfs.Count);

            m_digests.Clear(); // clear the current preserved digest state

            //
            // add the precalculated SignerInfo objects.
            //
            foreach (var signerInformation in _signers)
            {
                // TODO[cms] Avoid inconsistency b/w digestAlgorithms and signer digest algorithms?
                CmsUtilities.AddDigestAlgorithms(digestAlgorithmsBuilder, signerInformation);

                // TODO Verify the content type and calculated digest match the precalculated SignerInfo
                signerInfos.Add(signerInformation.ToSignerInfo());
            }

            //
            // add the SignerInfo objects
            //
            DerObjectIdentifier encapContentType = new DerObjectIdentifier(signedContentType);

            foreach (var signerInf in signerInfs)
            {
                try
                {
                    var signerInfo = signerInf.ToSignerInfo(encapContentType, content);

                    // TODO[cms] Avoid inconsistency b/w digestAlgorithms and signer digest algorithms?
                    digestAlgorithmsBuilder.Add(signerInfo.DigestAlgorithm);

                    signerInfos.Add(signerInfo);
                }
                catch (IOException e)
                {
                    throw new CmsException("encoding error.", e);
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for signature.", e);
                }
                catch (SignatureException e)
                {
                    throw new CmsException("error creating signature.", e);
                }
                catch (CertificateEncodingException e)
                {
                    throw new CmsException("error creating sid.", e);
                }
            }

            Asn1Set certificates = CreateAsn1Set(_certs, _useDerForCerts, _useDefiniteLength);

            Asn1Set crls = CreateAsn1Set(_crls, _useDerForCrls, _useDefiniteLength);

            Asn1OctetString encapContent = null;
            if (encapsulate)
            {
                try
                {
                    byte[] encapContentOctets = CmsUtilities.GetByteArray(content);

                    if (_useDefiniteLength)
                    {
                        encapContent = new DerOctetString(encapContentOctets);
                    }
                    else
                    {
                        encapContent = new BerOctetString(encapContentOctets);
                    }
                }
                catch (IOException e)
                {
                    throw new CmsException("encapsulation error.", e);
                }
            }

            ContentInfo encapContentInfo = new ContentInfo(encapContentType, encapContent);

            SignedData signedData = new SignedData(
                digestAlgorithmsBuilder.Build(),
                encapContentInfo,
                certificates,
                crls,
                DerSet.FromVector(signerInfos));

            ContentInfo contentInfo = new ContentInfo(CmsObjectIdentifiers.SignedData, signedData);

            return new CmsSignedData(content, contentInfo);
        }

        /**
         * generate a set of one or more SignerInformation objects representing counter signatures on
         * the passed in SignerInformation object.
         *
         * @param signer the signer to be countersigned
         * @param sigProvider the provider to be used for counter signing.
         * @return a store containing the signers.
         */
        public SignerInformationStore GenerateCounterSigners(SignerInformation signer)
        {
            m_digests.Clear();

            CmsProcessable content = new CmsProcessableByteArray(signer.GetSignature());

            var signerInformations = new List<SignerInformation>();

            foreach (SignerInformation _signer in _signers)
            {
                var signerInfo = _signer.ToSignerInfo();
                signerInformations.Add(new SignerInformation(signerInfo, null, content, null));
            }

            foreach (SignerInf signerInf in signerInfs)
            {
                try
                {
                    var signerInfo = signerInf.ToSignerInfo(null, content);
                    signerInformations.Add(new SignerInformation(signerInfo, null, content, null));
                }
                catch (IOException e)
                {
                    throw new CmsException("encoding error.", e);
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for signature.", e);
                }
                catch (SignatureException e)
                {
                    throw new CmsException("error creating signature.", e);
                }
                catch (CertificateEncodingException e)
                {
                    throw new CmsException("error creating sid.", e);
                }
            }

            return new SignerInformationStore(signerInformations);
        }

        public bool UseDefiniteLength
        {
            get { return _useDefiniteLength; }
            set { this._useDefiniteLength = value; }
        }

        private static Asn1Set CreateAsn1Set(IReadOnlyCollection<Asn1Encodable> elements, bool useDer, bool useDL)
        {
            return elements.Count < 1
                ?  null
                :  useDer
                ?  CmsUtilities.ToDerSet(elements)
                :  useDL
                ?  CmsUtilities.ToDLSet(elements)
                :  CmsUtilities.ToBerSet(elements);
        }
    }
}
