using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /**
     * General class for generating a pkcs7-signature message stream.
     * <p>
     * A simple example of usage.
     * </p>
     * <pre>
     *      IX509Store                   certs...
     *      CmsSignedDataStreamGenerator gen = new CmsSignedDataStreamGenerator();
     *
     *      gen.AddSigner(privateKey, cert, CmsSignedDataStreamGenerator.DIGEST_SHA1);
     *
     *      gen.AddCertificates(certs);
     *
     *      Stream sigOut = gen.Open(bOut);
     *
     *      sigOut.Write(Encoding.UTF8.GetBytes("Hello World!"));
     *
     *      sigOut.Close();
     * </pre>
     */
    public class CmsSignedDataStreamGenerator
        : CmsSignedGenerator
    {
        private readonly List<SignerInfoGeneratorImpl> m_signerInfoGens = new List<SignerInfoGeneratorImpl>();
        private readonly HashSet<DerObjectIdentifier> m_messageDigestOids = new HashSet<DerObjectIdentifier>();
        private readonly Dictionary<DerObjectIdentifier, IDigest> m_messageDigests =
            new Dictionary<DerObjectIdentifier, IDigest>();
        private bool _messageDigestsLocked;
        private int _bufferSize;

        private class SignerInfoGeneratorImpl
        {
            private readonly CmsSignedDataStreamGenerator m_outer;

            private readonly SignerIdentifier m_signerID;
            internal readonly AlgorithmIdentifier m_digAlgID;
            private readonly DerObjectIdentifier m_sigAlgOid;
            private readonly CmsAttributeTableGenerator m_sAttrGen;
            private readonly CmsAttributeTableGenerator m_unsAttrGen;
            private readonly string m_encName;
            private readonly ISigner m_signer;

            internal SignerInfoGeneratorImpl(
                CmsSignedDataStreamGenerator outer,
                AsymmetricKeyParameter key,
                SignerIdentifier signerID,
                DerObjectIdentifier digAlgOid,
                DerObjectIdentifier sigAlgOid,
                CmsAttributeTableGenerator sAttrGen,
                CmsAttributeTableGenerator unsAttrGen)
            {
                var encName = CmsSignedHelper.GetEncryptionAlgName(sigAlgOid);
                string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                string signatureName = digestName + "with" + encName;

                ISigner signer;
                if (sAttrGen != null)
                {
                    signer = SignerUtilities.InitSigner(signatureName, true, key, outer.m_random);
                }
                else
                {
                    // Note: Need to use raw signatures here since we have already calculated the digest
                    if ("RSA" == encName)
                    {
                        signer = SignerUtilities.InitSigner("RSA", true, key, outer.m_random);
                    }
                    else if ("DSA" == encName)
                    {
                        signer = SignerUtilities.InitSigner("NONEwithDSA", true, key, outer.m_random);
                    }
                    //TODO Add support for raw PSS
                    //else if ("RSAandMGF1" == encName)
                    //{
                    //    signer = SignerUtilities.GetSigner("NONEWITHRSAPSS");
                    //    try
                    //    {
                    //        // Init the params this way to avoid having a 'raw' version of each PSS algorithm
                    //        Signature sig2 = SignerUtilities.GetSigner(signatureName);
                    //        PSSParameterSpec spec = (PSSParameterSpec)sig2.getParameters().getParameterSpec(
                    //            typeof(PSSParameterSpec));
                    //        signer.setParameter(spec);
                    //    }
                    //    catch (Exception e)
                    //    {
                    //        throw new SignatureException("algorithm: " + encName + " could not be configured.", e);
                    //    }
                    //}
                    else
                    {
                        throw new SignatureException("algorithm: " + m_encName + " not supported in base signatures.");
                    }
                }

                m_outer = outer;
                m_signerID = signerID;
                m_digAlgID = outer.DigestAlgorithmFinder.Find(digAlgOid);
                m_sigAlgOid = sigAlgOid;
                m_sAttrGen = sAttrGen;
                m_unsAttrGen = unsAttrGen;
                m_encName = encName;
                m_signer = signer;
            }

            internal int GeneratedVersion => m_signerID.IsTagged ? 3 : 1;

            internal SignerInfo Generate(DerObjectIdentifier contentType, byte[] calculatedDigest)
            {
                AlgorithmIdentifier digAlgID = m_digAlgID;
                DerObjectIdentifier digAlgOid = digAlgID.Algorithm;

                try
                {
                    string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                    string signatureName = digestName + "with" + m_encName;

                    byte[] bytesToSign = calculatedDigest;

                    /* RFC 3852 5.4
                     * The result of the message digest calculation process depends on
                     * whether the signedAttrs field is present.  When the field is absent,
                     * the result is just the message digest of the content as described
                     *
                     * above.  When the field is present, however, the result is the message
                     * digest of the complete DER encoding of the SignedAttrs value
                     * contained in the signedAttrs field.
                     */
                    Asn1Set signedAttr = null;
                    if (m_sAttrGen != null)
                    {
                        var parameters = m_outer.GetBaseParameters(contentType, digAlgID, calculatedDigest);

                        Asn1.Cms.AttributeTable signed = m_sAttrGen.GetAttributes(
                            CollectionUtilities.ReadOnly(parameters));

                        if (contentType == null) //counter signature
                        {
                            signed = signed?.Remove(CmsAttributes.ContentType);
                        }

                        signedAttr = m_outer.GetAttributeSet(signed);

                        // sig must be composed from the DER encoding.
                        bytesToSign = signedAttr.GetEncoded(Asn1Encodable.Der);
                    }
                    else
                    {
                        // Note: Need to use raw signatures here since we have already calculated the digest
                        if (m_encName.Equals("RSA"))
                        {
                            DigestInfo dInfo = new DigestInfo(digAlgID, calculatedDigest);
                            bytesToSign = dInfo.GetEncoded(Asn1Encodable.Der);
                        }
                    }

                    m_signer.BlockUpdate(bytesToSign, 0, bytesToSign.Length);
                    byte[] sigBytes = m_signer.GenerateSignature();

                    Asn1Set unsignedAttr = null;
                    if (m_unsAttrGen != null)
                    {
                        var parameters = m_outer.GetBaseParameters(contentType, digAlgID, calculatedDigest);
                        parameters[CmsAttributeTableParameter.Signature] = sigBytes.Clone();

                        Asn1.Cms.AttributeTable unsigned = m_unsAttrGen.GetAttributes(
                            CollectionUtilities.ReadOnly(parameters));

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
                catch (IOException e)
                {
                    throw new CmsStreamException("encoding error.", e);
                }
                catch (SignatureException e)
                {
                    throw new CmsStreamException("error creating signature.", e);
                }
            }
        }

        public CmsSignedDataStreamGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsSignedDataStreamGenerator(SecureRandom random)
            : base(random)
        {
        }

        /**
        * Set the underlying string size for encapsulated data
        *
        * @param bufferSize length of octet strings to buffer the data.
        */
        public void SetBufferSize(int bufferSize)
        {
            _bufferSize = bufferSize;
        }

        public void AddDigests(params string[] digestOids)
        {
            foreach (string digestOid in digestOids)
            {
                ConfigureDigest(new DerObjectIdentifier(digestOid));
            }
        }

        public void AddDigests(IEnumerable<string> digestOids)
        {
            foreach (string digestOid in digestOids)
            {
                ConfigureDigest(new DerObjectIdentifier(digestOid));
            }
        }

        /**
        * add a signer - no attributes other than the default ones will be
        * provided here.
        * @throws NoSuchAlgorithmException
        * @throws InvalidKeyException
        */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOid) =>
            AddSigner(privateKey, cert, digestOid, new DefaultSignedAttributeTableGenerator(), null);

        /**
         * add a signer, specifying the digest encryption algorithm - no attributes other than the default ones will be
         * provided here.
         * @throws NoSuchProviderException
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOid,
            string digestOid)
        {
            AddSigner(privateKey, cert, encryptionOid, digestOid, new DefaultSignedAttributeTableGenerator(), null);
        }

        /**
         * add a signer with extra signed/unsigned attributes.
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOid,
            Asn1.Cms.AttributeTable	signedAttr, Asn1.Cms.AttributeTable	unsignedAttr)
        {
            AddSigner(privateKey, cert, digestOid, new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr));
        }

        /**
         * add a signer with extra signed/unsigned attributes - specifying digest
         * encryption algorithm.
         * @throws NoSuchProviderException
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOid,
            string digestOid, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, cert, encryptionOid, digestOid, new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOid,
            CmsAttributeTableGenerator signedAttrGenerator, CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOid)?.GetID(), digestOid,
                signedAttrGenerator, unsignedAttrGenerator);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOid,
            string digestOid, CmsAttributeTableGenerator signedAttrGenerator,
            CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOid),
                new DerObjectIdentifier(digestOid), signedAttrGenerator, unsignedAttrGenerator);
        }

        /**
         * add a signer - no attributes other than the default ones will be
         * provided here.
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOid) =>
            AddSigner(privateKey, subjectKeyID, digestOid, new DefaultSignedAttributeTableGenerator(), null);

        /**
         * add a signer - no attributes other than the default ones will be
         * provided here.
         * @throws NoSuchProviderException
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOid,
            string digestOid)
        {
            AddSigner(privateKey, subjectKeyID, encryptionOid, digestOid, new DefaultSignedAttributeTableGenerator(),
                null);
        }

        /**
         * add a signer with extra signed/unsigned attributes.
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOid,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, subjectKeyID, digestOid, new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr));
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOid,
            CmsAttributeTableGenerator signedAttrGenerator, CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOid)?.GetID(), digestOid,
                signedAttrGenerator, unsignedAttrGenerator);
        }

        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOid,
            string digestOid, CmsAttributeTableGenerator signedAttrGenerator,
            CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOid),
                new DerObjectIdentifier(digestOid), signedAttrGenerator, unsignedAttrGenerator);
        }

        private void DoAddSigner(AsymmetricKeyParameter privateKey, SignerIdentifier signerIdentifier,
            DerObjectIdentifier encryptionOid, DerObjectIdentifier digestOid,
            CmsAttributeTableGenerator signedAttrGenerator, CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            ConfigureDigest(digestOid);

            SignerInfoGeneratorImpl signerInfoGen = new SignerInfoGeneratorImpl(this, privateKey,
                signerIdentifier, digestOid, encryptionOid, signedAttrGenerator, unsignedAttrGenerator);

            m_signerInfoGens.Add(signerInfoGen);
        }

        internal override void AddSignerCallback(SignerInformation signerInformation)
        {
            // FIXME If there were parameters in signerInformation.DigestAlgorithmID.Parameters, they are lost
            // NB: Would need to call FixAlgID on the DigestAlgorithmID

            // For precalculated signers, just need to register the algorithm, not configure a digest
            RegisterDigestOid(signerInformation.DigestAlgorithmID.Algorithm);
        }

        /**
         * generate a signed object that for a CMS Signed Data object
         */
        public Stream Open(Stream outStream) => Open(outStream, encapsulate: false);

        /**
        * generate a signed object that for a CMS Signed Data
        * object - if encapsulate is true a copy
        * of the message will be included in the signature with the
        * default content type "data".
        */
        public Stream Open(Stream outStream, bool encapsulate) => Open(outStream, signedContentType: Data, encapsulate);

        /**
         * generate a signed object that for a CMS Signed Data
         * object using the given provider - if encapsulate is true a copy
         * of the message will be included in the signature with the
         * default content type "data". If dataOutputStream is non null the data
         * being signed will be written to the stream as it is processed.
         * @param out stream the CMS object is to be written to.
         * @param encapsulate true if data should be encapsulated.
         * @param dataOutputStream output stream to copy the data being signed to.
         */
        public Stream Open(Stream outStream, bool encapsulate, Stream dataOutputStream) =>
            Open(outStream, signedContentType: Data, encapsulate, dataOutputStream);

        /**
        * generate a signed object that for a CMS Signed Data
        * object - if encapsulate is true a copy
        * of the message will be included in the signature. The content type
        * is set according to the OID represented by the string signedContentType.
        */
        public Stream Open(Stream outStream, string signedContentType, bool encapsulate) =>
            Open(outStream, signedContentType, encapsulate, dataOutputStream: null);

        /**
         * generate a signed object that for a CMS Signed Data
         * object using the given provider - if encapsulate is true a copy
         * of the message will be included in the signature. The content type
         * is set according to the OID represented by the string signedContentType.
         * @param out stream the CMS object is to be written to.
         * @param signedContentType OID for data to be signed.
         * @param encapsulate true if data should be encapsulated.
         * @param dataOutputStream output stream to copy the data being signed to.
         */
        public Stream Open(Stream outStream, string signedContentType, bool encapsulate, Stream dataOutputStream)
        {
            if (outStream == null)
                throw new ArgumentNullException(nameof(outStream));
            if (!outStream.CanWrite)
                throw new ArgumentException("Expected writeable stream", nameof(outStream));
            if (dataOutputStream != null && !dataOutputStream.CanWrite)
                throw new ArgumentException("Expected writeable stream", nameof(dataOutputStream));

            _messageDigestsLocked = true;

            //
            // ContentInfo
            //
            BerSequenceGenerator sGen = new BerSequenceGenerator(outStream);

            sGen.AddObject(CmsObjectIdentifiers.SignedData);

            //
            // Signed Data
            //
            BerSequenceGenerator sigGen = new BerSequenceGenerator(sGen.GetRawOutputStream(), 0, true);

            DerObjectIdentifier contentTypeOid = new DerObjectIdentifier(signedContentType);

            sigGen.AddObject(CalculateVersion(contentTypeOid));

            DerSet digestAlgs = DerSet.Map(m_messageDigestOids, DigestAlgorithmFinder.Find);

            digestAlgs.EncodeTo(sigGen.GetRawOutputStream());

            BerSequenceGenerator eiGen = new BerSequenceGenerator(sigGen.GetRawOutputStream());
            eiGen.AddObject(contentTypeOid);

            BerOctetStringGenerator octGen = null;
            Stream encapStream = null;

            // If encapsulating, add the data as an octet string in the sequence
            if (encapsulate)
            {
                octGen = new BerOctetStringGenerator(eiGen.GetRawOutputStream(), 0, true);
                encapStream = octGen.GetOctetOutputStream(_bufferSize);
            }

            // Also send the data to 'dataOutputStream' if necessary
            Stream teeStream = GetSafeTeeOutputStream(dataOutputStream, encapStream);

            // Let all the digests see the data as it is written
            Stream digStream = AttachDigestsToOutputStream(m_messageDigests.Values, teeStream);

            return new CmsSignedDataOutputStream(this, digStream, contentTypeOid, sGen, sigGen, eiGen, octGen);
        }

        private void RegisterDigestOid(DerObjectIdentifier digestOid)
        {
            if (!_messageDigestsLocked)
            {
                m_messageDigestOids.Add(digestOid);
            }
            else if (!m_messageDigestOids.Contains(digestOid))
            {
                throw new InvalidOperationException("Cannot register new digest OIDs after the data stream is opened");
            }
        }

        private void ConfigureDigest(DerObjectIdentifier digestOid)
        {
            RegisterDigestOid(digestOid);

            if (!m_messageDigests.ContainsKey(digestOid))
            {
                if (_messageDigestsLocked)
                    throw new InvalidOperationException("Cannot configure new digests after the data stream is opened");

                m_messageDigests[digestOid] = DigestUtilities.GetDigest(digestOid);
            }
        }

        // TODO Make public?
        internal void Generate(Stream outStream, string eContentType, bool encapsulate, Stream dataOutputStream,
            CmsProcessable content)
        {
            using (var signedOut = Open(outStream, eContentType, encapsulate, dataOutputStream))
            {
                if (content != null)
                {
                    content.Write(signedOut);
                }
            }
        }

        // RFC3852, section 5.1:
        // IF ((certificates is present) AND
        //    (any certificates with a type of other are present)) OR
        //    ((crls is present) AND
        //    (any crls with a type of other are present))
        // THEN version MUST be 5
        // ELSE
        //    IF (certificates is present) AND
        //       (any version 2 attribute certificates are present)
        //    THEN version MUST be 4
        //    ELSE
        //       IF ((certificates is present) AND
        //          (any version 1 attribute certificates are present)) OR
        //          (any SignerInfo structures are version 3) OR
        //          (encapContentInfo eContentType is other than id-data)
        //       THEN version MUST be 3
        //       ELSE version MUST be 1
        //
        private DerInteger CalculateVersion(DerObjectIdentifier contentOid)
        {
            bool otherCert = false;
            bool otherCrl = false;
            bool attrCertV1Found = false;
            bool attrCertV2Found = false;

            if (_certs != null)
            {
                foreach (object obj in _certs)
                {
                    if (obj is Asn1TaggedObject tagged)
                    {
                        if (tagged.TagNo == 1)
                        {
                            attrCertV1Found = true;
                        }
                        else if (tagged.TagNo == 2)
                        {
                            attrCertV2Found = true;
                        }
                        else if (tagged.TagNo == 3)
                        {
                            otherCert = true;
                            break;
                        }
                    }
                }
            }

            if (otherCert)
            {
                return DerInteger.Five;
            }

            if (_crls != null)
            {
                foreach (object obj in _crls)
                {
                    if (obj is Asn1TaggedObject)
                    {
                        otherCrl = true;
                        break;
                    }
                }
            }

            if (otherCrl)
            {
                return DerInteger.Five;
            }

            if (attrCertV2Found)
            {
                return DerInteger.Four;
            }

            if (attrCertV1Found || !CmsObjectIdentifiers.Data.Equals(contentOid) ||
                CheckForVersion3(_signers, m_signerInfoGens))
            {
                return DerInteger.Three;
            }

            return DerInteger.One;
        }

        private static Stream AttachDigestsToOutputStream(IEnumerable<IDigest> digests, Stream s)
        {
            Stream result = s;
            foreach (IDigest digest in digests)
            {
                result = GetSafeTeeOutputStream(result, new DigestSink(digest));
            }
            return result;
        }

        private static bool CheckForVersion3(IList<SignerInformation> signerInfos,
            IList<SignerInfoGeneratorImpl> signerInfoGens)
        {
            foreach (SignerInformation si in signerInfos)
            {
                SignerInfo s = si.ToSignerInfo();
                if (s.Version.HasValue(3))
                    return true;
            }

            foreach (SignerInfoGeneratorImpl signerInfoGen in signerInfoGens)
            {
                if (signerInfoGen.GeneratedVersion == 3)
                    return true;
            }

            return false;
        }

        private static Stream GetSafeOutputStream(Stream s) => s ?? Stream.Null;

        private static Stream GetSafeTeeOutputStream(Stream s1, Stream s2)
        {
            if (s1 == null)
                return GetSafeOutputStream(s2);
            if (s2 == null)
                return GetSafeOutputStream(s1);
            return new TeeOutputStream(s1, s2);
        }

        private class CmsSignedDataOutputStream
            : BaseOutputStream
        {
            private readonly CmsSignedDataStreamGenerator outer;

            private Stream _out;
            private DerObjectIdentifier _contentOid;
            private BerSequenceGenerator _sGen;
            private BerSequenceGenerator _sigGen;
            private BerSequenceGenerator _eiGen;
            private BerOctetStringGenerator _octGen;

            internal CmsSignedDataOutputStream(CmsSignedDataStreamGenerator outer, Stream outStream,
                DerObjectIdentifier contentOid, BerSequenceGenerator sGen, BerSequenceGenerator sigGen,
                BerSequenceGenerator eiGen, BerOctetStringGenerator octGen)
            {
                this.outer = outer;

                _out = outStream;
                _contentOid = contentOid;
                _sGen = sGen;
                _sigGen = sigGen;
                _eiGen = eiGen;
                _octGen = octGen;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _out.Write(buffer, offset, count);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void Write(ReadOnlySpan<byte> buffer)
            {
                _out.Write(buffer);
            }
#endif

            public override void WriteByte(byte value)
            {
                _out.WriteByte(value);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    DoClose();
                }
                base.Dispose(disposing);
            }

            private void DoClose()
            {
                _out.Dispose();

                // TODO Parent context(s) should really be be closed explicitly

                // Only for encapsulation
                _octGen?.Dispose();

                _eiGen.Dispose();

                outer.m_digests.Clear();    // clear the current preserved digest state

                if (outer._certs.Count > 0)
                {
                    Asn1Set certs = outer._useDerForCerts
                        ? CmsUtilities.ToDerSet(outer._certs)
                        : CmsUtilities.ToBerSet(outer._certs);

                    WriteToGenerator(_sigGen, new BerTaggedObject(false, 0, certs));
                }

                if (outer._crls.Count > 0)
                {
                    Asn1Set crls = outer._useDerForCrls
                        ? CmsUtilities.ToDerSet(outer._crls)
                        : CmsUtilities.ToBerSet(outer._crls);

                    WriteToGenerator(_sigGen, new BerTaggedObject(false, 1, crls));
                }

                //
                // Calculate the digest hashes
                //
                foreach (var de in outer.m_messageDigests)
                {
                    outer.m_digests.Add(de.Key, DigestUtilities.DoFinal(de.Value));
                }

                // TODO If the digest OIDs for precalculated signers weren't mixed in with
                // the others, we could fill in outer._digests here, instead of SignerInfoGenerator.Generate

                //
                // collect all the SignerInfo objects
                //
                Asn1EncodableVector signerInfos = new Asn1EncodableVector();

                //
                // add the generated SignerInfo objects
                //
                foreach (SignerInfoGeneratorImpl signerInfoGen in outer.m_signerInfoGens)
                {
                    var digestOid = signerInfoGen.m_digAlgID.Algorithm;

                    byte[] calculatedDigest = outer.m_digests[digestOid];

                    signerInfos.Add(signerInfoGen.Generate(_contentOid, calculatedDigest));
                }

                //
                // add the precalculated SignerInfo objects.
                //
                {
                    foreach (SignerInformation _signer in outer._signers)
                    {
                        // TODO Verify the content type and calculated digest match the precalculated SignerInfo
                        //if (!_signer.ContentType.Equals(_contentOID))
                        //{
                        //    // TODO The precalculated content type did not match - error?
                        //}

                        //byte[] calculatedDigest = (byte[])outer._digests[_signer.DigestAlgOid];
                        //if (calculatedDigest == null)
                        //{
                        //    // TODO We can't confirm this digest because we didn't calculate it - error?
                        //}
                        //else
                        //{
                        //    if (!Arrays.AreEqual(_signer.GetContentDigest(), calculatedDigest))
                        //    {
                        //        // TODO The precalculated digest did not match - error?
                        //    }
                        //}

                        signerInfos.Add(_signer.ToSignerInfo());
                    }
                }

                WriteToGenerator(_sigGen, DerSet.FromVector(signerInfos));

                _sigGen.Dispose();
                _sGen.Dispose();
            }

            private static void WriteToGenerator(Asn1Generator ag, Asn1Encodable ae)
            {
                ae.EncodeTo(ag.GetRawOutputStream());
            }
        }
    }
}
