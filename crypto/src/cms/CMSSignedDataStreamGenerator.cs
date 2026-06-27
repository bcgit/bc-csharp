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
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Streaming generator for CMS SignedData (PKCS#7 signed-data) messages. Configure signers with
    /// <see cref="AddSigner(AsymmetricKeyParameter, X509Certificate, string)"/> (and overloads), add
    /// certificates and CRLs via the base <see cref="CmsSignedGenerator"/> methods, then call
    /// <see cref="Open(Stream)"/> to obtain a <see cref="Stream"/> to which the content being signed is written.
    /// Closing that stream finalizes the CMS structure.
    /// </summary>
    /// <remarks>
    /// The returned stream must be closed (disposed) to finalize the CMS structure, i.e. to write the
    /// certificates, CRLs and signer infos. Closing the returned stream does <b>not</b> close the underlying
    /// stream passed to <c>Open</c>; callers are responsible for closing the underlying stream separately.
    /// <para>A simple example of usage:</para>
    /// <code>
    /// CmsSignedDataStreamGenerator gen = new CmsSignedDataStreamGenerator();
    /// gen.AddSigner(privateKey, cert, CmsSignedGenerator.DigestSha1);
    /// gen.AddCertificates(certs);
    /// using (Stream sigOut = gen.Open(bOut))
    /// {
    ///     sigOut.Write(Strings.ToUtf8ByteArray("Hello World!"));
    /// }
    /// </code>
    /// </remarks>
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
            private readonly AlgorithmIdentifier m_digAlgID;
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

            internal AlgorithmIdentifier DigestAlgorithm => m_digAlgID;

            internal int GeneratedVersion => m_signerID.IsTagged ? 3 : 1;

            internal SignerInfo Generate(DerObjectIdentifier contentType, byte[] calculatedDigest)
            {
                AlgorithmIdentifier digAlgID = m_digAlgID;
                DerObjectIdentifier digAlgOid = digAlgID.Algorithm;

                try
                {
                    string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                    string signatureName = digestName + "with" + m_encName;

                    // TODO[RSAPSS] Need the ability to specify non-default parameters
                    Asn1Encodable sigAlgParams = SignerUtilities.GetDefaultX509Parameters(signatureName);
                    AlgorithmIdentifier sigAlgID = CmsSignedHelper.GetSigAlgID(m_sigAlgOid, sigAlgParams);

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
                    Asn1Set signedAttrs = null;
                    if (m_sAttrGen != null)
                    {
                        var parameters = m_outer.GetBaseParameters(contentType, digAlgID, sigAlgID, calculatedDigest);

                        Asn1.Cms.AttributeTable signed = m_sAttrGen.GetAttributes(
                            CollectionUtilities.ReadOnly(parameters));

                        if (contentType == null) //counter signature
                        {
                            signed = signed?.Remove(CmsAttributes.ContentType);
                        }

                        signedAttrs = m_outer.GetAttributeSet(signed);

                        // sig must be composed from the DER encoding.
                        bytesToSign = signedAttrs.GetEncoded(Asn1Encodable.Der);
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

                    Asn1Set unsignedAttrs = null;
                    if (m_unsAttrGen != null)
                    {
                        var parameters = m_outer.GetBaseParameters(contentType, digAlgID, sigAlgID, calculatedDigest);
                        parameters[CmsAttributeTableParameter.Signature] = sigBytes.Clone();

                        Asn1.Cms.AttributeTable unsigned = m_unsAttrGen.GetAttributes(
                            CollectionUtilities.ReadOnly(parameters));

                        unsignedAttrs = m_outer.GetAttributeSet(unsigned);
                    }

                    if (m_sAttrGen == null)
                    {
                        // RFC 8419, Section 3.2 - needs to be shake-256, not shake-256-len
                        if (EdECObjectIdentifiers.id_Ed448.Equals(sigAlgID.Algorithm))
                        {
                            digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256);
                        }
                    }

                    var signature = new DerOctetString(sigBytes);

                    return new SignerInfo(m_signerID, digAlgID, signedAttrs, sigAlgID, signature, unsignedAttrs);
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

        /// <summary>Creates a generator using the default randomness source.</summary>
        public CmsSignedDataStreamGenerator()
        {
        }

        /// <summary>
        /// Creates a generator with an explicit randomness source for signature generation.
        /// </summary>
        /// <param name="random">The secure random to use when signing.</param>
        public CmsSignedDataStreamGenerator(SecureRandom random)
            : base(random)
        {
        }

        /// <summary>
        /// Sets the buffer size used for the OCTET STRING segments holding the encapsulated content.
        /// </summary>
        /// <param name="bufferSize">The length, in bytes, of the octet strings used to buffer the data.</param>
        public void SetBufferSize(int bufferSize)
        {
            _bufferSize = bufferSize;
        }

        /// <summary>Registers one or more digest algorithm OIDs to be computed over the signed content.</summary>
        /// <param name="digestOids">The digest algorithm OIDs to add.</param>
        public void AddDigests(params string[] digestOids)
        {
            foreach (string digestOid in digestOids)
            {
                ConfigureDigest(new DerObjectIdentifier(digestOid));
            }
        }

        /// <summary>Registers one or more digest algorithm OIDs to be computed over the signed content.</summary>
        /// <param name="digestOids">The digest algorithm OIDs to add.</param>
        public void AddDigests(IEnumerable<string> digestOids)
        {
            foreach (string digestOid in digestOids)
            {
                ConfigureDigest(new DerObjectIdentifier(digestOid));
            }
        }

        /// <summary>
        /// Adds a signer identified by certificate, inferring the signature algorithm OID from the key type.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOid) =>
            AddSigner(privateKey, cert, digestOid, new DefaultSignedAttributeTableGenerator(), null);

        /// <summary>
        /// Adds a signer identified by certificate with explicit digest and signature algorithm OIDs.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="encryptionOid">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOid,
            string digestOid)
        {
            AddSigner(privateKey, cert, encryptionOid, digestOid, new DefaultSignedAttributeTableGenerator(), null);
        }

        /// <summary>
        /// Adds a certificate-identified signer with caller-supplied signed and unsigned attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOid,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, cert, digestOid, new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr));
        }

        /// <summary>
        /// Adds a certificate-identified signer with explicit algorithm OIDs and attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="encryptionOid">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOid,
            string digestOid, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, cert, encryptionOid, digestOid, new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr));
        }

        /// <summary>
        /// Adds a certificate-identified signer with caller-supplied attribute table generators, inferring the
        /// signature algorithm OID from the key type.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttrGenerator">Generator producing the signed attribute table.</param>
        /// <param name="unsignedAttrGenerator">Generator producing the unsigned attribute table.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOid,
            CmsAttributeTableGenerator signedAttrGenerator, CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOid)?.GetID(), digestOid,
                signedAttrGenerator, unsignedAttrGenerator);
        }

        /// <summary>
        /// Adds a certificate-identified signer with explicit algorithm OIDs and attribute table generators.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="encryptionOid">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttrGenerator">Generator producing the signed attribute table.</param>
        /// <param name="unsignedAttrGenerator">Generator producing the unsigned attribute table.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOid,
            string digestOid, CmsAttributeTableGenerator signedAttrGenerator,
            CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOid),
                new DerObjectIdentifier(digestOid), signedAttrGenerator, unsignedAttrGenerator);
        }

        /// <summary>
        /// Adds a signer identified by subject key identifier, inferring the signature algorithm OID from the key.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOid) =>
            AddSigner(privateKey, subjectKeyID, digestOid, new DefaultSignedAttributeTableGenerator(), null);

        /// <summary>
        /// Adds a signer identified by subject key identifier with explicit digest and signature algorithm OIDs.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="encryptionOid">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOid,
            string digestOid)
        {
            AddSigner(privateKey, subjectKeyID, encryptionOid, digestOid, new DefaultSignedAttributeTableGenerator(),
                null);
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with caller-supplied signed and unsigned attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOid,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, subjectKeyID, digestOid, new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr));
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with caller-supplied attribute table generators, inferring the
        /// signature algorithm OID from the key type.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttrGenerator">Generator producing the signed attribute table.</param>
        /// <param name="unsignedAttrGenerator">Generator producing the unsigned attribute table.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOid,
            CmsAttributeTableGenerator signedAttrGenerator, CmsAttributeTableGenerator unsignedAttrGenerator)
        {
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOid)?.GetID(), digestOid,
                signedAttrGenerator, unsignedAttrGenerator);
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with explicit algorithm OIDs and attribute table generators.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="encryptionOid">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOid">The digest algorithm OID.</param>
        /// <param name="signedAttrGenerator">Generator producing the signed attribute table.</param>
        /// <param name="unsignedAttrGenerator">Generator producing the unsigned attribute table.</param>
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

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object. The content is signed but not encapsulated.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream) => Open(outStream, encapsulate: false);

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object using the default content type "data".
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="encapsulate">If <c>true</c>, a copy of the content is encapsulated in the signature.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream, bool encapsulate) =>
            Open(outStream, contentType: CmsObjectIdentifiers.Data, encapsulate);

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object using the default content type "data", optionally
        /// copying the content being signed to a second stream as it is processed.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="encapsulate">If <c>true</c>, a copy of the content is encapsulated in the signature.</param>
        /// <param name="dataOutputStream">An optional stream to copy the content being signed to; may be null.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream, bool encapsulate, Stream dataOutputStream) =>
            Open(outStream, contentType: CmsObjectIdentifiers.Data, encapsulate, dataOutputStream);

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object with the given encapsulated content type.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="signedContentType">The OID of the content type being signed.</param>
        /// <param name="encapsulate">If <c>true</c>, a copy of the content is encapsulated in the signature.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        [Obsolete("Use version taking a DerObjectIdentifier instead")]
        public Stream Open(Stream outStream, string signedContentType, bool encapsulate) =>
            Open(outStream, new DerObjectIdentifier(signedContentType), encapsulate);

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object with the given encapsulated content type, optionally
        /// copying the content being signed to a second stream as it is processed.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="signedContentType">The OID of the content type being signed.</param>
        /// <param name="encapsulate">If <c>true</c>, a copy of the content is encapsulated in the signature.</param>
        /// <param name="dataOutputStream">An optional stream to copy the content being signed to; may be null.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="outStream"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if a supplied stream is not writeable.</exception>
        [Obsolete("Use version taking a DerObjectIdentifier instead")]
        public Stream Open(Stream outStream, string signedContentType, bool encapsulate, Stream dataOutputStream) =>
            Open(outStream, new DerObjectIdentifier(signedContentType), encapsulate, dataOutputStream);

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object with the given encapsulated content type.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="contentType">The OID of the content type being signed.</param>
        /// <param name="encapsulate">If <c>true</c>, a copy of the content is encapsulated in the signature.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream, DerObjectIdentifier contentType, bool encapsulate) =>
            Open(outStream, contentType, encapsulate, dataOutputStream: null);

        /// <summary>
        /// Opens a stream for generating a CMS SignedData object with the given encapsulated content type, optionally
        /// copying the content being signed to a second stream as it is processed.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="contentType">The OID of the content type being signed.</param>
        /// <param name="encapsulate">If <c>true</c>, a copy of the content is encapsulated in the signature.</param>
        /// <param name="dataOutputStream">An optional stream to copy the content being signed to; may be null.</param>
        /// <returns>A stream the content being signed is written to; close it to finalize the structure.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="outStream"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if a supplied stream is not writeable.</exception>
        public Stream Open(Stream outStream, DerObjectIdentifier contentType, bool encapsulate, Stream dataOutputStream)
        {
            if (outStream == null)
                throw new ArgumentNullException(nameof(outStream));
            if (!outStream.CanWrite)
                throw new ArgumentException("Expected writeable stream", nameof(outStream));
            if (dataOutputStream != null && !dataOutputStream.CanWrite)
                throw new ArgumentException("Expected writeable stream", nameof(dataOutputStream));

            _messageDigestsLocked = true;

            // ContentInfo
            BerSequenceGenerator sGen = new BerSequenceGenerator(outStream);
            sGen.AddObject(CmsObjectIdentifiers.SignedData);

            // SignedData
            BerSequenceGenerator sigGen = new BerSequenceGenerator(sGen.GetRawOutputStream(), 0, true);
            sigGen.AddObject(CalculateVersion(contentType));
            sigGen.AddObject(DerSet.Map(m_messageDigestOids, DigestAlgorithmFinder.Find));

            // EncapsulatedContentInfo
            BerSequenceGenerator eciGen = new BerSequenceGenerator(sigGen.GetRawOutputStream());
            eciGen.AddObject(contentType);

            // eContent [0] EXPLICIT OCTET STRING OPTIONAL
            BerOctetStringGenerator ecGen = null;
            Stream ecStream = null;

            if (encapsulate)
            {
                ecGen = new BerOctetStringGenerator(eciGen.GetRawOutputStream(), 0, true);
                ecStream = ecGen.GetOctetOutputStream(_bufferSize);
            }

            // Also send the data to 'dataOutputStream' if necessary
            Stream teeStream = GetSafeTeeOutputStream(dataOutputStream, ecStream);

            // Let all the digests see the data as it is written
            Stream digStream = AttachDigestsToOutputStream(m_messageDigests.Values, teeStream);

            return new CmsSignedDataOutputStream(this, digStream, contentType, sGen, sigGen, eciGen, ecGen);
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
        internal void Generate(Stream outStream, DerObjectIdentifier contentType, bool encapsulate,
            Stream dataOutputStream, CmsProcessable content)
        {
            using (var signedOut = Open(outStream, contentType, encapsulate, dataOutputStream))
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
                if (si.SignerInfo.Version.HasValue(3))
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
            private readonly CmsSignedDataStreamGenerator m_outer;

            private Stream m_out;
            private DerObjectIdentifier m_contentType;
            private BerSequenceGenerator m_sGen;
            private BerSequenceGenerator m_sigGen;
            private BerSequenceGenerator m_eciGen;
            private BerOctetStringGenerator m_ecGen;

            internal CmsSignedDataOutputStream(CmsSignedDataStreamGenerator outer, Stream outStream,
                DerObjectIdentifier contentType, BerSequenceGenerator sGen, BerSequenceGenerator sigGen,
                BerSequenceGenerator eciGen, BerOctetStringGenerator ecGen)
            {
                m_outer = outer;

                m_out = outStream;
                m_contentType = contentType;
                m_sGen = sGen;
                m_sigGen = sigGen;
                m_eciGen = eciGen;
                m_ecGen = ecGen;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                m_out.Write(buffer, offset, count);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void Write(ReadOnlySpan<byte> buffer)
            {
                m_out.Write(buffer);
            }
#endif

            public override void WriteByte(byte value)
            {
                m_out.WriteByte(value);
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
                m_out.Dispose();

                // TODO Parent context(s) should really be be closed explicitly

                // Only for encapsulation
                m_ecGen?.Dispose();

                m_eciGen.Dispose();

                m_outer.m_digests.Clear();    // clear the current preserved digest state

                if (m_outer._certs.Count > 0)
                {
                    Asn1Set certs = m_outer._useDerForCerts
                        ? CmsUtilities.ToDerSet(m_outer._certs)
                        : CmsUtilities.ToBerSet(m_outer._certs);

                    m_sigGen.AddObject(new BerTaggedObject(false, 0, certs));
                }

                if (m_outer._crls.Count > 0)
                {
                    Asn1Set crls = m_outer._useDerForCrls
                        ? CmsUtilities.ToDerSet(m_outer._crls)
                        : CmsUtilities.ToBerSet(m_outer._crls);

                    m_sigGen.AddObject(new BerTaggedObject(false, 1, crls));
                }

                //
                // Calculate the digest hashes
                //
                foreach (var de in m_outer.m_messageDigests)
                {
                    m_outer.m_digests.Add(de.Key, DigestUtilities.DoFinal(de.Value));
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
                foreach (SignerInfoGeneratorImpl signerInfoGen in m_outer.m_signerInfoGens)
                {
                    var digestOid = signerInfoGen.DigestAlgorithm.Algorithm;

                    byte[] calculatedDigest = m_outer.m_digests[digestOid];

                    signerInfos.Add(signerInfoGen.Generate(m_contentType, calculatedDigest));
                }

                //
                // add the precalculated SignerInfo objects.
                //
                {
                    foreach (SignerInformation _signer in m_outer._signers)
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

                        signerInfos.Add(_signer.SignerInfo);
                    }
                }

                m_sigGen.AddObject(DerSet.FromVector(signerInfos));

                m_sigGen.Dispose();
                m_sGen.Dispose();
            }
        }
    }
}
