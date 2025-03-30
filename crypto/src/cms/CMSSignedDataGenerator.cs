using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Operators;
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
                string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(sigAlgOid);

                m_outer = outer;
                m_signatureFactory = new Asn1SignatureFactory(signatureName, key, random);
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

                m_outer = outer;
                m_signatureFactory = signatureFactory;
                m_signerID = signerID;
                // TODO Configure an IDigestAlgorithmFinder
                m_digAlgID = DefaultDigestAlgorithmFinder.Instance.Find(sigAlgID);
                m_sigAlgOid = sigAlgID.Algorithm;
                m_sAttrGen = sAttrGen;
                m_unsAttrGen = unsAttrGen;
                m_baseSignedTable = baseSignedTable;
            }

            internal SignerInfo ToSignerInfo(DerObjectIdentifier contentType, CmsProcessable content)
            {
                AlgorithmIdentifier digAlgID = m_digAlgID;
                DerObjectIdentifier digAlgOid = digAlgID.Algorithm;

                string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(m_sigAlgOid);

                if (!m_outer.m_digests.TryGetValue(digAlgOid, out var hash))
                {
                    IDigest dig = DigestUtilities.GetDigest(digAlgOid);
                    if (content != null)
                    {
                        content.Write(new DigestSink(dig));
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
                        // TODO Use raw signature of the hash value instead
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

                // TODO[RSAPSS] Need the ability to specify non-default parameters
                Asn1Encodable sigAlgParams = SignerUtilities.GetDefaultX509Parameters(signatureName);
                AlgorithmIdentifier sigAlgID = CmsSignedHelper.GetSigAlgID(m_sigAlgOid, sigAlgParams);

                if (m_sAttrGen == null)
                {
                    // RFC 8419, Section 3.2 - needs to be shake-256, not shake-256-len
                    if (EdECObjectIdentifiers.id_Ed448.Equals(sigAlgID.Algorithm))
                    {
                        digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);
                    }
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
        public void AddSigner(
            AsymmetricKeyParameter	privateKey,
            X509Certificate			cert,
            string					digestOID)
        {
        	AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID);
		}

		/**
		 * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
		 * provided here.
		 *
		 * @param key signing key to use
		 * @param cert certificate containing corresponding public key
		 * @param encryptionOID digest encryption algorithm OID
		 * @param digestOID digest algorithm OID
		 */
		public void AddSigner(
			AsymmetricKeyParameter	privateKey,
			X509Certificate			cert,
			string					encryptionOID,
			string					digestOID)
		{
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(), null, null);
		}

	    /**
	     * add a signer - no attributes other than the default ones will be
	     * provided here.
	     */
	    public void AddSigner(
            AsymmetricKeyParameter	privateKey,
	        byte[]					subjectKeyID,
            string					digestOID)
	    {
			AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID);
	    }

		/**
		 * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
		 * provided here.
		 */
		public void AddSigner(
			AsymmetricKeyParameter	privateKey,
			byte[]					subjectKeyID,
			string					encryptionOID,
			string					digestOID)
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
        public void AddSigner(
            AsymmetricKeyParameter	privateKey,
            X509Certificate			cert,
            string					digestOID,
            Asn1.Cms.AttributeTable	signedAttr,
            Asn1.Cms.AttributeTable	unsignedAttr)
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
		public void AddSigner(
			AsymmetricKeyParameter	privateKey,
			X509Certificate			cert,
			string					encryptionOID,
			string					digestOID,
			Asn1.Cms.AttributeTable	signedAttr,
			Asn1.Cms.AttributeTable	unsignedAttr)
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
		public void AddSigner(
			AsymmetricKeyParameter	privateKey,
			byte[]					subjectKeyID,
			string					digestOID,
			Asn1.Cms.AttributeTable	signedAttr,
			Asn1.Cms.AttributeTable	unsignedAttr)
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
		public void AddSigner(
			AsymmetricKeyParameter	privateKey,
			byte[]					subjectKeyID,
			string					encryptionOID,
			string					digestOID,
			Asn1.Cms.AttributeTable	signedAttr,
			Asn1.Cms.AttributeTable	unsignedAttr)
		{
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(signedAttr),
				new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
		}

		/**
		 * add a signer with extra signed/unsigned attributes based on generators.
		 */
		public void AddSigner(
			AsymmetricKeyParameter		privateKey,
			X509Certificate				cert,
			string						digestOID,
			CmsAttributeTableGenerator	signedAttrGen,
			CmsAttributeTableGenerator	unsignedAttrGen)
		{
			AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
				signedAttrGen, unsignedAttrGen);
		}

		/**
		 * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes based on generators.
		 */
		public void AddSigner(
			AsymmetricKeyParameter		privateKey,
			X509Certificate				cert,
			string						encryptionOID,
			string						digestOID,
			CmsAttributeTableGenerator	signedAttrGen,
			CmsAttributeTableGenerator	unsignedAttrGen)
		{
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), signedAttrGen, unsignedAttrGen, null);
		}

	    /**
	     * add a signer with extra signed/unsigned attributes based on generators.
	     */
	    public void AddSigner(
			AsymmetricKeyParameter		privateKey,
	        byte[]						subjectKeyID,
	        string						digestOID,
	        CmsAttributeTableGenerator	signedAttrGen,
	        CmsAttributeTableGenerator	unsignedAttrGen)
	    {
			AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
				signedAttrGen, unsignedAttrGen);
	    }

		/**
		 * add a signer, including digest encryption algorithm, with extra signed/unsigned attributes based on generators.
		 */
		public void AddSigner(
			AsymmetricKeyParameter		privateKey,
			byte[]						subjectKeyID,
			string						encryptionOID,
			string						digestOID,
			CmsAttributeTableGenerator	signedAttrGen,
			CmsAttributeTableGenerator	unsignedAttrGen)
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

        private void DoAddSigner(
			AsymmetricKeyParameter		privateKey,
			SignerIdentifier            signerIdentifier,
			DerObjectIdentifier         encryptionOid,
			DerObjectIdentifier         digestOid,
			CmsAttributeTableGenerator  signedAttrGen,
			CmsAttributeTableGenerator  unsignedAttrGen,
			Asn1.Cms.AttributeTable		baseSignedTable)
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
            string			signedContentType,
			// FIXME Avoid accessing more than once to support CmsProcessableInputStream
            CmsProcessable	content,
            bool			encapsulate)
        {
            Asn1EncodableVector digestAlgs = new Asn1EncodableVector();
            Asn1EncodableVector signerInfos = new Asn1EncodableVector();

			m_digests.Clear(); // clear the current preserved digest state

			//
            // add the precalculated SignerInfo objects.
            //
            foreach (SignerInformation _signer in _signers)
            {
                // TODO Configure an IDigestAlgorithmFinder
                CmsUtilities.AddDigestAlgs(digestAlgs, _signer, DefaultDigestAlgorithmFinder.Instance);
                // TODO Verify the content type and calculated digest match the precalculated SignerInfo
                signerInfos.Add(_signer.ToSignerInfo());
            }

			//
            // add the SignerInfo objects
            //
            DerObjectIdentifier encapContentType = new DerObjectIdentifier(signedContentType);

            foreach (SignerInf signerInf in signerInfs)
            {
                try
                {
                    var signerInfo = signerInf.ToSignerInfo(encapContentType, content);
                    digestAlgs.Add(signerInfo.DigestAlgorithm);
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

            Asn1Set certificates = CreateSetFromList(_certs, _useDerForCerts);

            Asn1Set crls = CreateSetFromList(_crls, _useDerForCrls);

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
                DerSet.FromVector(digestAlgs),
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

        private Asn1Set CreateSetFromList(List<Asn1Encodable> list, bool useDer)
        {
            return list.Count < 1
                ?  null
                :  useDer
                ?  CmsUtilities.CreateDerSetFromList(list)
                :  _useDefiniteLength
                ?  CmsUtilities.CreateDLSetFromList(list)
                :  CmsUtilities.CreateBerSetFromList(list);
        }
    }
}
