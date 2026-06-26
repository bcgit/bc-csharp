using System;
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
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Generator for CMS SignedData (PKCS#7 signed-data) messages. Configure signers with
    /// <see cref="AddSigner(AsymmetricKeyParameter, X509Certificate, string)"/> (and overloads), add
    /// certificates and CRLs via the base <see cref="CmsSignedGenerator"/> methods, then call
    /// <see cref="Generate(CmsTypedData, bool)"/> to obtain a <see cref="CmsSignedData"/> instance.
    /// </summary>
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
                //        throw new ArgumentException(
                //            "Ed448 cannot be used with this constructor and signed attributes");
                //    }

                //    var sigAlgID = new AlgorithmIdentifier(sigAlgOid);

                //    signatureFactory = new Asn1SignatureFactory(sigAlgID, key, random);
                //}
                else if (MLDsaParameters.ByOid.TryGetValue(sigAlgOid, out MLDsaParameters mlDsaParameters))
                {
                    if (mlDsaParameters.IsPreHash)
                        throw new CmsException($"{mlDsaParameters} prehash signature is not supported");

                    // TODO[cms] Add mechanism for checking whether dig. alg. is usable for given pure-mode sig. alg.
                    if (!NistObjectIdentifiers.IdSha512.Equals(digAlgOid) &&
                        !NistObjectIdentifiers.IdShake256.Equals(digAlgOid))
                    {
                        throw new CmsException($"{mlDsaParameters} signature used with unsupported digest algorithm");
                    }

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
                m_digAlgID = outer.DigestAlgorithmFinder.Find(digAlgOid);
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

                    digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
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

                    // TODO[cms] Allow SignerInfoGenerator customization of dig. alg. to use with pure-mode sig. alg.
                    digAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
                }
                else if (SlhDsaParameters.ByOid.TryGetValue(sigAlgOid, out SlhDsaParameters slhDsaParameters))
                {
                    if (slhDsaParameters.IsPreHash)
                        throw new CmsException($"{slhDsaParameters} prehash signature is not supported");

                    if (sigAlgParams != null)
                        throw new CmsException($"{slhDsaParameters} signature cannot specify algorithm parameters");

                    // TODO[cms] Allow SignerInfoGenerator customization of dig. alg. to use with pure-mode sig. alg.
                    var defaultDigAlgOid = CmsSignedHelper.GetSlhDsaDigestOid(sigAlgOid);
                    digAlgID = new AlgorithmIdentifier(defaultDigAlgOid);
                }
                else
                {
                    digAlgID = outer.DigestAlgorithmFinder.Find(sigAlgID);
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

                Asn1Set signedAttrs = null;

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

                        signedAttrs = m_outer.GetAttributeSet(signed);

                        // sig must be composed from the DER encoding.
                        signedAttrs.EncodeTo(sigStr, Asn1Encodable.Der);
                    }
                    else if (content != null)
                    {
                        // TODO Use raw signature of the hash value instead (when sig alg uses external digest)
                        content.Write(sigStr);
                    }
                }

                byte[] sigBytes = calculator.GetResult().Collect();

                Asn1Set unsignedAttrs = null;
                if (m_unsAttrGen != null)
                {
                    var baseParameters = m_outer.GetBaseParameters(contentType, digAlgID, hash);
                    baseParameters[CmsAttributeTableParameter.Signature] = sigBytes.Clone();

                    Asn1.Cms.AttributeTable unsigned = m_unsAttrGen.GetAttributes(
                        CollectionUtilities.ReadOnly(baseParameters));

                    // TODO Validate proposed unsigned attributes

                    unsignedAttrs = m_outer.GetAttributeSet(unsigned);
                }

                AlgorithmIdentifier sigAlgID;
                if (EdECObjectIdentifiers.id_Ed25519.Equals(m_sigAlgOid))
                {
                    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid);
                }
                //else if (EdECObjectIdentifiers.id_Ed448.Equals(m_sigAlgOid))
                //{
                //    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid);
                //}
                else if (MLDsaParameters.ByOid.TryGetValue(m_sigAlgOid, out MLDsaParameters mlDsaParameters))
                {
                    Debug.Assert(!mlDsaParameters.IsPreHash);
                    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid);
                }
                else if (SlhDsaParameters.ByOid.TryGetValue(m_sigAlgOid, out SlhDsaParameters slhDsaParameters))
                {
                    Debug.Assert(!slhDsaParameters.IsPreHash);
                    sigAlgID = new AlgorithmIdentifier(m_sigAlgOid);
                }
                else
                {
                    string digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                    string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(m_sigAlgOid);

                    // TODO[RSAPSS] Need the ability to specify non-default parameters
                    Asn1Encodable sigAlgParams = SignerUtilities.GetDefaultX509Parameters(signatureName);
                    sigAlgID = CmsSignedHelper.GetSigAlgID(m_sigAlgOid, sigAlgParams);
                }

                var signature = new DerOctetString(sigBytes);

                return new SignerInfo(m_signerID, digAlgID, signedAttrs, sigAlgID, signature, unsignedAttrs);
            }
        }

        /// <summary>Creates a generator using the default randomness source.</summary>
        public CmsSignedDataGenerator()
        {
        }

        /// <summary>
        /// Creates a generator with an explicit randomness source for signature generation.
        /// </summary>
        /// <param name="random">The secure random to use when signing.</param>
        public CmsSignedDataGenerator(SecureRandom random)
            : base(random)
        {
        }

        /// <summary>
        /// Adds a signer identified by certificate, inferring the signature algorithm OID from the key type.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID) =>
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID);

        /// <summary>
        /// Adds a signer identified by certificate with explicit digest and signature algorithm OIDs.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="encryptionOID">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID,
            string digestOID)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(), null, null);
        }

        /// <summary>
        /// Adds a signer identified by subject key identifier, inferring the signature algorithm OID from the key.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID) =>
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID);

        /// <summary>
        /// Adds a signer identified by subject key identifier with explicit digest and signature algorithm OIDs.
        /// Only default signed attributes are included.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="encryptionOID">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID,
            string digestOID)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(), null, null);
        }

        /// <summary>
        /// Adds a certificate-identified signer with caller-supplied signed and unsigned attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttr, unsignedAttr);
        }

        /// <summary>
        /// Adds a certificate-identified signer with explicit algorithm OIDs and attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="encryptionOID">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID,
            string digestOID, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with caller-supplied signed and unsigned attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID,
            Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttr, unsignedAttr);
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with explicit algorithm OIDs and attribute tables.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="encryptionOID">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttr">Signed attributes to include (merged with defaults).</param>
        /// <param name="unsignedAttr">Unsigned attributes to include.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID,
            string digestOID, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr), signedAttr);
        }

        /// <summary>
        /// Adds a certificate-identified signer with attribute-table generators for signed and unsigned attributes.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttrGen">Generator for signed attributes.</param>
        /// <param name="unsignedAttrGen">Generator for unsigned attributes.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string digestOID,
            CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            AddSigner(privateKey, cert, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttrGen, unsignedAttrGen);
        }

        /// <summary>
        /// Adds a certificate-identified signer with explicit algorithm OIDs and attribute-table generators.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="cert">The signer's X.509 certificate.</param>
        /// <param name="encryptionOID">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttrGen">Generator for signed attributes.</param>
        /// <param name="unsignedAttrGen">Generator for unsigned attributes.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, X509Certificate cert, string encryptionOID,
            string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(cert), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), signedAttrGen, unsignedAttrGen, null);
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with attribute-table generators.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttrGen">Generator for signed attributes.</param>
        /// <param name="unsignedAttrGen">Generator for unsigned attributes.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string digestOID,
            CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            AddSigner(privateKey, subjectKeyID, CmsSignedHelper.GetEncOid(privateKey, digestOID)?.GetID(), digestOID,
                signedAttrGen, unsignedAttrGen);
        }

        /// <summary>
        /// Adds a subject-key-id-identified signer with explicit algorithm OIDs and attribute-table generators.
        /// </summary>
        /// <param name="privateKey">The signing private key.</param>
        /// <param name="subjectKeyID">The subject key identifier octets.</param>
        /// <param name="encryptionOID">The signature (encryption) algorithm OID.</param>
        /// <param name="digestOID">The digest algorithm OID.</param>
        /// <param name="signedAttrGen">Generator for signed attributes.</param>
        /// <param name="unsignedAttrGen">Generator for unsigned attributes.</param>
        public void AddSigner(AsymmetricKeyParameter privateKey, byte[] subjectKeyID, string encryptionOID,
            string digestOID, CmsAttributeTableGenerator signedAttrGen, CmsAttributeTableGenerator unsignedAttrGen)
        {
            DoAddSigner(privateKey, GetSignerIdentifier(subjectKeyID), new DerObjectIdentifier(encryptionOID),
                new DerObjectIdentifier(digestOID), signedAttrGen, unsignedAttrGen, null);
        }

        /// <summary>
        /// Adds a signer using a pre-configured <see cref="SignerInfoGenerator"/>.
        /// </summary>
        /// <param name="signerInfoGenerator">The signer configuration to add.</param>
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

        /// <summary>
        /// Generates a CMS SignedData object for <paramref name="content"/> without encapsulating the content.
        /// </summary>
        /// <param name="content">The content to sign.</param>
        /// <returns>The signed-data structure.</returns>
        /// <exception cref="CmsException">
        /// An error occurred while building signer information or encapsulating content.
        /// </exception>
        [Obsolete("Use 'Generate(CmsTypedData)' instead")]
        public CmsSignedData Generate(CmsProcessable content) => Generate(content, encapsulate: false);

        /// <summary>
        /// Generates a CMS SignedData object, optionally encapsulating a copy of the content with type <c>data</c>.
        /// </summary>
        /// <param name="content">The content to sign.</param>
        /// <param name="encapsulate"><c>true</c> to embed the content in the SignedData.</param>
        /// <returns>The signed-data structure.</returns>
        /// <exception cref="CmsException">
        /// An error occurred while building signer information or encapsulating content.
        /// </exception>
        [Obsolete("Use 'Generate(CmsTypedData, bool)' instead")]
        public CmsSignedData Generate(CmsProcessable content, bool encapsulate) =>
            Generate(CmsUtilities.GetTypedData(content), encapsulate);

        /// <summary>
        /// Generates a CMS SignedData object with an explicit encapsulated content type OID.
        /// </summary>
        /// <param name="signedContentType">Dotted-decimal OID of the encapsulated content type.</param>
        /// <param name="content">The content to sign.</param>
        /// <param name="encapsulate"><c>true</c> to embed the content in the SignedData.</param>
        /// <returns>The signed-data structure.</returns>
        /// <exception cref="CmsException">
        /// An error occurred while building signer information or encapsulating content.
        /// </exception>
        [Obsolete("Use 'Generate(CmsTypedData, bool)' instead")]
        public CmsSignedData Generate(string signedContentType, CmsProcessable content, bool encapsulate) =>
            Generate(CmsUtilities.BindTypedData(new DerObjectIdentifier(signedContentType), content), encapsulate);

        /// <summary>
        /// Generates a CMS SignedData object for <paramref name="content"/> without encapsulating the content.
        /// </summary>
        /// <param name="content">The content to sign. <c>null</c> is not allowed; use a <see cref="CmsAbsentContent"/>
        /// instead to signal no content.</param>
        /// <returns>The signed-data structure.</returns>
        /// <exception cref="CmsException">
        /// An error occurred while building signer information or encapsulating content.
        /// </exception>
        public CmsSignedData Generate(CmsTypedData content) => Generate(content, encapsulate: false);

        /// <summary>
        /// Generate a CMS SignedData object for <paramref name="content"/>, which can be carrying a detached CMS
        /// signature, or have encapsulated data, depending on the value of <paramref name="encapsulate"/>.
        /// </summary>
        /// <param name="content">The content to sign. <c>null</c> is not allowed; use a <see cref="CmsAbsentContent"/>
        /// instead to signal no content.</param>
        /// <param name="encapsulate">
        /// <c>true</c> if the content should be encapsulated in the signature, <c>false</c> otherwise.
        /// </param>
        /// <returns>The signed-data structure.</returns>
        /// <exception cref="CmsException">
        /// An error occurred while building signer information or encapsulating content.
        /// </exception>
        public CmsSignedData Generate(
            // FIXME Avoid accessing more than once to support CmsProcessableInputStream
            CmsTypedData content,
            bool encapsulate)
        {
            if (content == null)
                throw new ArgumentNullException(nameof(content));

            var digestAlgorithmsBuilder = new DigestAlgorithmsBuilder(DigestAlgorithmFinder);

            var signerInfos = new List<SignerInfo>(_signers.Count + signerInfs.Count);

            m_digests.Clear(); // clear the current preserved digest state

            //
            // add the precalculated SignerInfo objects.
            //
            foreach (var signerInformation in _signers)
            {
                // TODO[cms] Avoid inconsistency b/w digestAlgorithms and signer digest algorithms?
                CmsUtilities.AddDigestAlgorithms(digestAlgorithmsBuilder, signerInformation);

                // TODO Verify the content type and calculated digest match the precalculated SignerInfo
                signerInfos.Add(signerInformation.SignerInfo);
            }

            //
            // add the SignerInfo objects
            //
            DerObjectIdentifier encapContentType = content.ContentType;

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

            Asn1Set certificates = _certs.ToAsn1SetOptional(_useDerForCerts, _useDefiniteLength);

            Asn1Set crls = _crls.ToAsn1SetOptional(_useDerForCrls, _useDefiniteLength);

            Asn1OctetString encapContent = null;

            // bc-java checks typedData.getContent() but we don't have such a method/property
            if (encapsulate && !(content is CmsAbsentContent))
            {
                try
                {
                    byte[] encapContentOctets = CmsUtilities.GetByteArray(content);

                    if (_useDefiniteLength)
                    {
                        encapContent = DerOctetString.WithContents(encapContentOctets);
                    }
                    else
                    {
                        encapContent = BerOctetString.WithContents(encapContentOctets);
                    }
                }
                catch (IOException e)
                {
                    throw new CmsException("encapsulation error.", e);
                }
            }

            ContentInfo encapContentInfo = new ContentInfo(encapContentType, encapContent);

            SignedData signedData = new SignedData(
                digestAlgorithmsBuilder.Build(useDL: UseDefiniteLength),
                encapContentInfo,
                certificates,
                crls,
                signerInfos.ToAsn1Set(useDer: false, useDL: UseDefiniteLength));

            var contentInfo = new ContentInfo(CmsObjectIdentifiers.SignedData, signedData);

            return new CmsSignedData(content, contentInfo);
        }

        /// <summary>
        /// Generates counter-signature SignerInformation objects over an existing signer's signature value.
        /// </summary>
        /// <param name="signer">The signer to countersign.</param>
        /// <returns>A store containing the counter-signature signer informations.</returns>
        /// <exception cref="CmsException">An error occurred while creating counter signatures.</exception>
        public SignerInformationStore GenerateCounterSigners(SignerInformation signer)
        {
            m_digests.Clear();

            DerObjectIdentifier contentType = null;

            CmsTypedData content = new CmsProcessableByteArray(contentType, signer.GetSignature());

            var signerInformations = new List<SignerInformation>();

            foreach (SignerInformation _signer in _signers)
            {
                signerInformations.Add(new SignerInformation(_signer.SignerInfo, contentType, content, null));
            }

            foreach (SignerInf signerInf in signerInfs)
            {
                try
                {
                    var signerInfo = signerInf.ToSignerInfo(contentType, content);
                    signerInformations.Add(new SignerInformation(signerInfo, contentType, content, null));
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

        /// <summary>
        /// When <c>true</c>, generated SignedData structures use definite-length (DL) encoding where supported.
        /// </summary>
        public bool UseDefiniteLength
        {
            get { return _useDefiniteLength; }
            set { this._useDefiniteLength = value; }
        }
    }
}
