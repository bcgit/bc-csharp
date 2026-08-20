using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Represents an expanded CMS <c>SignerInfo</c> from a signed-data message. Obtain instances from
    /// <see cref="CmsSignedData.GetSignerInfos"/>, match signers with <see cref="SignerID"/>, then call
    /// <see cref="Verify(AsymmetricKeyParameter)"/> or <see cref="Verify(X509Certificate)"/>.
    /// </summary>
    public class SignerInformation
    {
        private SignerID sid;

        private CmsProcessable content;
        private byte[] signature;
        private DerObjectIdentifier contentType;
        private byte[] calculatedDigest;
        private byte[] resultDigest;

        // Derived
        private Asn1.Cms.AttributeTable m_signedAttributeTable;
        private Asn1.Cms.AttributeTable m_unsignedAttributeTable;
        private readonly bool isCounterSignature;

        // TODO[api] Avoid having protected fields (maybe seal the class too?)
        protected SignerInfo info;
        protected AlgorithmIdentifier digestAlgorithm;
        // TODO[api] Rename to 'signatureAlgorithm'
        protected AlgorithmIdentifier encryptionAlgorithm;
        protected readonly Asn1Set signedAttributeSet;
        protected readonly Asn1Set unsignedAttributeSet;

        internal SignerInformation(SignerInfo info, DerObjectIdentifier contentType, CmsProcessable content,
            byte[] calculatedDigest)
        {
            this.info = info;
            this.sid = new SignerID();
            this.contentType = contentType;
            this.isCounterSignature = contentType == null;

            try
            {
                SignerIdentifier s = info.SignerID;

                if (s.IsTagged)
                {
                    var subjectKeyIdentifier = SubjectKeyIdentifier.GetInstance(s.ID);

                    sid.SubjectKeyIdentifier = subjectKeyIdentifier.GetEncoded(Asn1Encodable.Der);
                }
                else
                {
                    var issuerAndSerialNumber = IssuerAndSerialNumber.GetInstance(s.ID);

                    sid.Issuer = issuerAndSerialNumber.Issuer;
                    sid.SerialNumber = issuerAndSerialNumber.SerialNumber.Value;
                }
            }
            catch (IOException)
            {
                throw new ArgumentException("invalid sid in SignerInfo");
            }

            this.digestAlgorithm = info.DigestAlgorithm;
            this.signedAttributeSet = info.SignedAttrs;
            this.unsignedAttributeSet = info.UnsignedAttrs;
            this.encryptionAlgorithm = info.SignatureAlgorithm;
            this.signature = Arrays.Clone(info.Signature.GetOctets());

            this.content = content;
            this.calculatedDigest = calculatedDigest;
        }

        /// <summary>
        /// Initializes a new instance based on <paramref name="baseInfo"/> for subclasses that override
        /// signed-attribute handling or signature calculation.
        /// </summary>
        /// <param name="baseInfo">The signer information to copy state from.</param>
        protected SignerInformation(SignerInformation baseInfo)
        {
            this.info = baseInfo.info;
            this.content = baseInfo.content;
            this.contentType = baseInfo.contentType;
            this.isCounterSignature = baseInfo.IsCounterSignature;
            this.sid = baseInfo.sid;
            this.digestAlgorithm = info.DigestAlgorithm;
            this.signedAttributeSet = info.SignedAttrs;
            this.unsignedAttributeSet = info.UnsignedAttrs;
            this.encryptionAlgorithm = info.SignatureAlgorithm;
            this.signature = Arrays.Clone(info.Signature.GetOctets());

            this.calculatedDigest = baseInfo.calculatedDigest;
            m_signedAttributeTable = baseInfo.m_signedAttributeTable;
            m_unsignedAttributeTable = baseInfo.m_unsignedAttributeTable;
        }

        /// <summary>Gets a value indicating whether this signer information represents a counter signature.</summary>
        public bool IsCounterSignature => isCounterSignature;

        /// <summary>Gets the content type of the signed data, or null for a counter signature.</summary>
        public DerObjectIdentifier ContentType => contentType;

        /// <summary>Gets the identifier used to match this signer against certificates.</summary>
        public SignerID SignerID => sid;

        /// <summary>Gets the <c>SignerInfo</c> version number.</summary>
        public int Version => info.Version.IntValueExact;

        // TODO[api] Rename to DigestAlgorithm (after field made non-visible and/or renamed)
        /// <summary>Gets the digest algorithm identifier from the underlying <c>SignerInfo</c>.</summary>
        public AlgorithmIdentifier DigestAlgorithmID => digestAlgorithm;

        /// <summary>Gets the digest algorithm OID. Use <see cref="DigestAlgorithmID"/> instead.</summary>
        [Obsolete("Use 'DigestAlgorithmID' instead")]
        public string DigestAlgOid => digestAlgorithm.Algorithm.GetID();

        /// <summary>
        /// Gets the digest algorithm parameters, or null if absent. Use <see cref="DigestAlgorithmID"/> instead.
        /// </summary>
        [Obsolete("Use 'DigestAlgorithmID' instead")]
        public Asn1Object DigestAlgParams => digestAlgorithm.Parameters?.ToAsn1Object();

        /// <summary>Returns the content digest calculated during the most recent successful verification.</summary>
        /// <returns>A copy of the calculated digest.</returns>
        /// <exception cref="InvalidOperationException">Verification has not been performed yet.</exception>
        public byte[] GetContentDigest()
        {
            if (resultDigest == null)
                throw new InvalidOperationException("method can only be called after verify.");

            return (byte[])resultDigest.Clone();
        }

        /// <summary>Gets the signature algorithm identifier. Use <see cref="SignatureAlgorithm"/> instead.</summary>
        [Obsolete("Use 'SignatureAlgorithm' property instead")]
        public AlgorithmIdentifier EncryptionAlgorithmID => encryptionAlgorithm;

        /// <summary>Gets the signature algorithm OID. Use <see cref="SignatureAlgorithm"/> instead.</summary>
        [Obsolete("Use 'SignatureAlgorithm' property instead")]
        public string EncryptionAlgOid => encryptionAlgorithm.Algorithm.Id;

        /// <summary>
        /// Gets the signature algorithm parameters, or null if absent. Use <see cref="SignatureAlgorithm"/> instead.
        /// </summary>
        [Obsolete("Use 'SignatureAlgorithm' property instead")]
        public Asn1Object EncryptionAlgParams => encryptionAlgorithm.Parameters?.ToAsn1Object();

        /// <summary>Gets the signature algorithm identifier from the underlying <c>SignerInfo</c>.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => encryptionAlgorithm;

        /// <summary>Gets a table of signed attributes indexed by attribute OID.</summary>
        public Asn1.Cms.AttributeTable SignedAttributes
        {
            get
            {
                if (m_signedAttributeTable == null)
                {
                    m_signedAttributeTable = signedAttributeSet?.ToAttributeTable();
                }
                return m_signedAttributeTable;
            }
        }

        /// <summary>Gets the underlying ASN.1 <c>SignerInfo</c> structure.</summary>
        public SignerInfo SignerInfo => info;

        /// <summary>Gets the underlying ASN.1 <c>SignerInfo</c> structure. Use <see cref="SignerInfo"/> instead.
        /// </summary>
        [Obsolete("Use 'SignerInfo' property instead")]
        public SignerInfo ToSignerInfo() => info;

        /// <summary>Gets a table of unsigned attributes indexed by attribute OID.</summary>
        public Asn1.Cms.AttributeTable UnsignedAttributes
        {
            get
            {
                if (m_unsignedAttributeTable == null)
                {
                    m_unsignedAttributeTable = unsignedAttributeSet?.ToAttributeTable();
                }
                return m_unsignedAttributeTable;
            }
        }

        /// <summary>Returns a copy of the encoded signature value.</summary>
        public byte[] GetSignature() => Arrays.Clone(signature);

        /// <summary>
        /// Returns counter signatures attached to this signer as unsigned attributes, or an empty store if none are
        /// present.
        /// </summary>
        public SignerInformationStore GetCounterSignatures()
        {
            // TODO There are several checks implied by the RFC3852 comments that are missing

            /*
             * The countersignature attribute MUST be an unsigned attribute; it MUST
             * NOT be a signed attribute, an authenticated attribute, an
             * unauthenticated attribute, or an unprotected attribute.
             */
            Asn1.Cms.AttributeTable unsignedAttributes = UnsignedAttributes;
            if (unsignedAttributes == null)
                return new SignerInformationStore(new List<SignerInformation>(0));

            var counterSignatures = new List<SignerInformation>();

            /*
             * The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
             * UnsignedAttributes in a signerInfo may include multiple instances of
             * the countersignature attribute.
             */
            Asn1EncodableVector allCSAttrs = unsignedAttributes.GetAll(CmsAttributes.CounterSignature);

            foreach (Asn1.Cms.Attribute counterSignatureAttribute in allCSAttrs)
            {
                /*
                 * A countersignature attribute can have multiple attribute values.  The
                 * syntax is defined as a SET OF AttributeValue, and there MUST be one
                 * or more instances of AttributeValue present.
                 */
                Asn1Set values = counterSignatureAttribute.AttrValues;
                if (values.Count < 1)
                {
                    // TODO Throw an appropriate exception?
                }

                foreach (var signerInfo in CollectionUtilities.Select(values, SignerInfo.GetInstance))
                {
                    /*
                     * Countersignature values have the same meaning as SignerInfo values
                     * for ordinary signatures, except that:
                     * 
                     *   1. The signedAttributes field MUST NOT contain a content-type
                     *      attribute; there is no content type for countersignatures.
                     * 
                     *   2. The signedAttributes field MUST contain a message-digest
                     *      attribute if it contains any other attributes.
                     * 
                     *   3. The input to the message-digesting process is the contents
                     *      octets of the DER encoding of the signatureValue field of the
                     *      SignerInfo value with which the attribute is associated.
                     */
                    byte[] hash = DigestUtilities.CalculateDigest(signerInfo.DigestAlgorithm.Algorithm, signature);

                    counterSignatures.Add(new SignerInformation(signerInfo, null, null, hash));
                }
            }

            return new SignerInformationStore(counterSignatures);
        }

        /// <summary>Returns the DER encoding of the signed attributes, or null if none are present.</summary>
        /// <exception cref="IOException">An encoding error occurs.</exception>
        public virtual byte[] GetEncodedSignedAttributes() => signedAttributeSet?.GetEncoded(Asn1Encodable.Der);

        private bool DoVerify(AsymmetricKeyParameter publicKey)
        {
            var digAlgID = DigestAlgorithmID;
            var digAlgOid = digAlgID.Algorithm;
            var digAlgParams = digAlgID.Parameters;

            var sigAlgID = SignatureAlgorithm;
            var sigAlgOid = sigAlgID.Algorithm;
            var sigAlgParams = sigAlgID.Parameters;

            string digestName;
            ISigner sig;

            if (EdECObjectIdentifiers.id_Ed25519.Equals(sigAlgOid))
            {
                if (sigAlgParams != null)
                    throw new CmsException("Ed25519 signature cannot specify algorithm parameters");

                if (signedAttributeSet == null)
                {
                    digestName = null;
                }
                else
                {
                    if (!NistObjectIdentifiers.IdSha512.Equals(digAlgOid) || digAlgParams != null)
                        throw new CmsException("Ed25519 signature used with unsupported digest algorithm");

                    digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                }

                sig = SignerUtilities.GetSigner(sigAlgOid);
            }
            //else if (EdECObjectIdentifiers.id_Ed448.Equals(sigAlgOid))
            //{
            //    if (sigAlgParams != null)
            //        throw new CmsException("Ed448 signature cannot specify algorithm parameters");

            //    if (signedAttributeSet == null)
            //    {
            //        digestName = null;
            //    }
            //    else
            //    {
            //        var expectedAlgID = new AlgorithmIdentifier(NistObjectIdentifiers.IdShake256Len, new DerInteger(512));

            //        if (!expectedAlgID.Equals(digAlgID))
            //            throw new CmsException("Ed448 signature used with unsupported digest algorithm");

            //        //digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
            //        digestName = "SHAKE256-512";
            //    }

            //    sig = SignerUtilities.GetSigner(sigAlgOid);
            //}
            else if (MLDsaParameters.ByOid.TryGetValue(sigAlgOid, out MLDsaParameters mlDsaParameters))
            {
                if (mlDsaParameters.IsPreHash)
                    throw new CmsException($"{mlDsaParameters} prehash signature is not supported");

                if (sigAlgParams != null)
                    throw new CmsException($"{mlDsaParameters} signature cannot specify algorithm parameters");

                if (signedAttributeSet == null)
                {
                    /*
                     * draft-ietf-lamps-cms-ml-dsa-03 3.3. When processing a SignerInfo signed using ML-DSA, if no signed
                     * attributes are present, implementations MUST ignore the content of the digestAlgorithm field.
                     */
                    digestName = null;
                }
                else
                {
                    /*
                     * draft-ietf-lamps-cms-ml-dsa-03 3.3. When SHA-512 is used, the id-sha512 [..] digest algorithm
                     * identifier is used and the parameters field MUST be omitted. When SHAKE256 is used, the
                     * id-shake256 [..] digest algorithm identifier is used and produces 512 bits of output, and the
                     * parameters field MUST be omitted.
                     */
                    // TODO[cms] Add mechanism for checking whether dig. alg. is usable for given pure-mode sig. alg.
                    if (!NistObjectIdentifiers.IdSha512.Equals(digAlgOid) &&
                        !NistObjectIdentifiers.IdShake256.Equals(digAlgOid))
                    {
                        throw new CmsException($"{mlDsaParameters} signature used with unsupported digest algorithm");
                    }

                    if (digAlgParams != null)
                        throw new CmsException($"{mlDsaParameters} signature used with unsupported digest algorithm");

                    digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                }

                sig = SignerUtilities.GetSigner(sigAlgOid);
            }
            else if (SlhDsaParameters.ByOid.TryGetValue(sigAlgOid, out SlhDsaParameters slhDsaParameters))
            {
                if (slhDsaParameters.IsPreHash)
                    throw new CmsException($"{slhDsaParameters} prehash signature is not supported");

                if (sigAlgParams != null)
                    throw new CmsException($"{slhDsaParameters} signature cannot specify algorithm parameters");

                /*
                 * TODO[cms] Check this is being met (presumably by the signer checks on the public key parameter set)
                 *
                 * draft-ietf-lamps-cms-sphincs-plus-19 4. Signature verification MUST include checking that the
                 * signatureAlgorithm field identifies SLH-DSA parameters that are consistent with public key used to
                 * validate the signature.
                 */

                /*
                 * TODO[cms] Note somewhat of a contradiction here for signed-attributes-present behaviour
                 * 
                 * draft-ietf-lamps-cms-sphincs-plus-19 4.
                 *
                 * When signed attributes are absent, the SLH-DSA (pure mode) signature is computed over the content.
                 * When signed attributes are present, a hash MUST be computed over the content using the same hash
                 * function that is used in the SLH-DSA tree.
                 *
                 * When signed attributes are absent, the digestAlgorithm identifier MUST match the hash function used
                 * in the SLH-DSA tree (as shown in the list below). When signed attributes are present, to ensure
                 * collision resistance, the identified hash function MUST produce a hash value that is at least twice
                 * the size of the hash function used in the SLH-DSA tree.
                 */
                if (signedAttributeSet == null)
                {
                    digestName = null;
                }
                else
                {
                    var defaultDigAlgOid = CmsSignedHelper.GetSlhDsaDigestOid(sigAlgOid);
                    if (!defaultDigAlgOid.Equals(digAlgOid) || digAlgParams != null)
                        throw new CmsException($"{slhDsaParameters} signature used with unsupported digest algorithm");

                    digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                }

                sig = SignerUtilities.GetSigner(sigAlgOid);
            }
            else if (Asn1.Pkcs.PkcsObjectIdentifiers.IdRsassaPss.Equals(sigAlgOid))
            {
                // RFC 4056 2.2
                // When the id-RSASSA-PSS algorithm identifier is used for a signature,
                // the AlgorithmIdentifier parameters field MUST contain RSASSA-PSS-params.
                if (sigAlgParams == null)
                    throw new CmsException("RSASSA-PSS signature must specify algorithm parameters");

                try
                {
                    // TODO Provide abstract configuration mechanism
                    // (via alternate SignerUtilities.GetSigner method taking ASN.1 params)

                    Asn1.Pkcs.RsassaPssParameters pss = Asn1.Pkcs.RsassaPssParameters.GetInstance(sigAlgParams);

                    if (!pss.HashAlgorithm.Algorithm.Equals(digAlgOid))
                        throw new CmsException("RSASSA-PSS signature parameters specified incorrect hash algorithm");
                    if (!pss.MaskGenAlgorithm.Algorithm.Equals(Asn1.Pkcs.PkcsObjectIdentifiers.IdMgf1))
                        throw new CmsException("RSASSA-PSS signature parameters specified unknown MGF");

                    IDigest pssDigest = DigestUtilities.GetDigest(digAlgOid);
                    int saltLength = pss.SaltLength.IntValueExact;

                    // RFC 4055 3.1
                    // The value MUST be 1, which represents the trailer field with hexadecimal value 0xBC
                    if (!Asn1.Pkcs.RsassaPssParameters.DefaultTrailerField.Equals(pss.TrailerField))
                        throw new CmsException("RSASSA-PSS signature parameters must have trailerField of 1");

                    digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);

                    IAsymmetricBlockCipher rsa = new RsaBlindedEngine();

                    if (signedAttributeSet == null)
                    {
                        sig = PssSigner.CreateRawSigner(rsa, pssDigest, saltLength);
                    }
                    else
                    {
                        sig = new PssSigner(rsa, pssDigest, saltLength);
                    }
                }
                catch (Exception e)
                {
                    throw new CmsException("failed to set RSASSA-PSS signature parameters", e);
                }
            }
            else
            {
                if (!X509Utilities.IsAbsentParameters(sigAlgParams))
                    throw new CmsException("unrecognised signature parameters provided");

                digestName = CmsSignedHelper.GetDigestAlgName(sigAlgOid);
                if (digestName.Equals(sigAlgOid.GetID()))
                {
                    digestName = CmsSignedHelper.GetDigestAlgName(digAlgOid);
                }

                // TODO Create raw verifier in case signedAttributeSet == null? (as for id-RSASSA-PSS above)

                string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(sigAlgOid);

                sig = CmsSignedHelper.GetSignatureInstance(signatureName);

                //sig = CmsSignedHelper.GetSignatureInstance(this.EncryptionAlgOid);
                //sig = CmsSignedHelper.GetSignatureInstance(sigAlgOid);
            }

            try
            {
                if (signedAttributeSet == null && digestName == null)
                {
                    if (content == null)
                    {
                        // TODO Get rid of this exception and just treat content==null as empty not missing?
                        throw new CmsException("data not encapsulated in signature - use detached constructor.");
                    }

                    resultDigest = null;
                }
                else if (calculatedDigest != null)
                {
                    resultDigest = calculatedDigest;
                }
                else
                {
                    var digest = CmsSignedHelper.GetDigestInstance(digestName);

                    if (content != null)
                    {
                        using (var stream = new DigestSink(digest))
                        {
                            content.Write(stream);
                        }
                    }
                    else if (signedAttributeSet == null)
                    {
                        // TODO Get rid of this exception and just treat content==null as empty not missing?
                        throw new CmsException("data not encapsulated in signature - use detached constructor.");
                    }

                    resultDigest = DigestUtilities.DoFinal(digest);
                }
            }
            catch (IOException e)
            {
                throw new CmsException("can't process mime object to create signature.", e);
            }

            // RFC 3852 11.1 Check the content-type attribute is correct
            VerifyContentTypeAttributeValue();

            // RFC 6211 Validate Algorithm Protection attribute if present
            VerifyAlgorithmProtectionAttribute();

            // RFC 3852 11.2 Check the message-digest attribute is correct
            VerifyMessageDigestAttribute();

            // RFC 3852 11.4 Validate countersignature attribute(s)
            VerifyCounterSignatureAttribute();

            try
            {
                if (signedAttributeSet != null)
                    return VerifySignature(sig, publicKey, GetEncodedSignedAttributes(), signature);

                // sig was created as a raw id-RSASSA-PSS signer above
                if (sig is PssSigner)
                    return VerifySignature(sig, publicKey, resultDigest, signature);

                if (resultDigest != null && TryGetRawVerifier(out var rawVerifier))
                    return VerifySignature(rawVerifier, publicKey, resultDigest, signature);

                sig.Init(false, publicKey);

                // Currently would already have thrown if null, but leave test in case null will mean "empty"
                if (content != null)
                {
                    using (var stream = new SignerSink(sig))
                    {
                        content.Write(stream);
                    }
                }

                return sig.VerifySignature(signature);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key not appropriate to signature in message.", e);
            }
            catch (IOException e)
            {
                throw new CmsException("can't process mime object to create signature.", e);
            }
            catch (SignatureException e)
            {
                throw new CmsException("invalid signature format in message: " + e.Message, e);
            }
        }

        /// <summary>RFC 3852 11.1 Check the content-type attribute is correct.</summary>
        private void VerifyContentTypeAttributeValue()
        {
            Asn1Encodable validContentType = GetSingleValuedSignedAttribute(CmsAttributes.ContentType, "content-type");
            if (validContentType == null)
            {
                if (!isCounterSignature && signedAttributeSet != null)
                    throw new CmsException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
            }
            else
            {
                if (isCounterSignature)
                    throw new CmsException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");

                if (!(validContentType is DerObjectIdentifier signedContentType))
                    throw new CmsException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");

                if (!signedContentType.Equals(contentType))
                    throw new CmsException("content-type attribute value does not match eContentType");
            }
        }

        /// <summary>RFC 3852 11.2 Check the message-digest attribute is correct.</summary>
        private void VerifyMessageDigestAttribute()
        {
            Asn1Encodable validMessageDigest = GetSingleValuedSignedAttribute(CmsAttributes.MessageDigest,
                "message-digest");
            if (validMessageDigest == null)
            {
                if (signedAttributeSet != null)
                    throw new CmsException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
            }
            else
            {
                if (!(validMessageDigest is Asn1OctetString signedMessageDigest))
                    throw new CmsException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");

                if (!Arrays.FixedTimeEquals(resultDigest, signedMessageDigest.GetOctets()))
                    throw new CmsException("message-digest attribute value does not match calculated value");
            }
        }

        /// <summary>RFC 6211 Validate Algorithm Protection attribute if present.</summary>
        private void VerifyAlgorithmProtectionAttribute()
        {
            Asn1Encodable validAlgorithmProtection = GetSingleValuedSignedAttribute(CmsAttributes.CmsAlgorithmProtect,
                "cmsAlgorithmProtect");
            if (validAlgorithmProtection != null)
            {
                var algorithmProtection = CmsAlgorithmProtection.GetInstance(validAlgorithmProtection);

                if (!CmsUtilities.IsEquivalent(algorithmProtection.DigestAlgorithm, info.DigestAlgorithm))
                    throw new CmsException("CMS Algorithm Protection check failed for digestAlgorithm");

                if (!CmsUtilities.IsEquivalent(algorithmProtection.SignatureAlgorithm, info.SignatureAlgorithm))
                    throw new CmsException("CMS Algorithm Protection check failed for signatureAlgorithm");
            }
        }

        private void VerifyCounterSignatureAttribute()
        {
            Asn1.Cms.AttributeTable signedAttributes = SignedAttributes;
            if (signedAttributes != null && signedAttributes.HasAny(CmsAttributes.CounterSignature))
                throw new CmsException("A countersignature attribute MUST NOT be a signed attribute");

            Asn1.Cms.AttributeTable unsignedAttributes = UnsignedAttributes;
            if (unsignedAttributes != null)
            {
                foreach (Asn1.Cms.Attribute csAttr in unsignedAttributes.GetAll(CmsAttributes.CounterSignature))
                {
                    if (csAttr.AttrValues.Count < 1)
                        throw new CmsException("A countersignature attribute MUST contain at least one AttributeValue");

                    // Note: We don't recursively validate the countersignature value
                }
            }
        }

        private bool TryGetRawVerifier(out ISigner rawVerifier)
        {
            string algorithm = CmsSignedHelper.GetEncryptionAlgName(SignatureAlgorithm.Algorithm);

            // TODO GOST, ECGOST?

            if ("RSA".Equals(algorithm))
            {
                rawVerifier = new RsaDigestSigner(new NullDigest(), digestAlgorithm);
            }
            else if ("ECDSA".Equals(algorithm))
            {
                rawVerifier = CmsSignedHelper.GetSignatureInstance("NONEwithECDSA");
            }
            else if ("PLAIN-ECDSA".Equals(algorithm))
            {
                rawVerifier = CmsSignedHelper.GetSignatureInstance("NONEwithPLAIN-ECDSA");
            }
            else if ("DSA".Equals(algorithm))
            {
                rawVerifier = CmsSignedHelper.GetSignatureInstance("NONEwithDSA");
            }
            else
            {
                rawVerifier = default;
                return false;
            }
            return true;
        }

        /// <summary>
        /// Verifies the signature using <paramref name="pubKey"/> and validates signed attributes when present.
        /// </summary>
        /// <param name="pubKey">The signer's public key.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentException"><paramref name="pubKey"/> is a private key.</exception>
        /// <exception cref="CmsException">The signature or signed attributes cannot be processed.</exception>
        public bool Verify(AsymmetricKeyParameter pubKey)
        {
            if (pubKey.IsPrivate)
                throw new ArgumentException("Expected public key", nameof(pubKey));

            // Optional, but still need to validate if present
            GetSigningTime();

            // No associated certificate to check signingTime against

            return DoVerify(pubKey);
        }

        /// <summary>
        /// Verify that the given certificate successfully handles and confirms the signature associated with this
        /// signer.
        /// </summary>
        /// <param name="cert">The signer's certificate.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="CmsVerifierCertificateNotValidException">The certificate was not valid at signing time.
        /// </exception>
        /// <exception cref="CmsException">The signature or signed attributes cannot be processed.</exception>
        /// <remarks>
        /// If a signingTime attribute is available, it is checked that the certificate was valid at the indicated
        /// time.
        /// </remarks>
        public bool Verify(X509Certificate cert)
        {
            Asn1.Cms.Time signingTime = GetSigningTime();
            if (signingTime != null)
            {
                if (!cert.IsValid(signingTime.ToDateTime()))
                    throw new CmsVerifierCertificateNotValidException("verifier not valid at signingTime");
            }

            return DoVerify(cert.GetPublicKey());
        }

        private Asn1Encodable GetSingleValuedSignedAttribute(DerObjectIdentifier attrOid, string printableName)
        {
            var unsignedAttributes = UnsignedAttributes;
            if (unsignedAttributes != null && unsignedAttributes.HasAny(attrOid))
                throw new CmsException($"The {printableName} attribute MUST NOT be an unsigned attribute");

            var signedAttributes = SignedAttributes;
            if (signedAttributes == null)
                return null;

            Asn1EncodableVector v = signedAttributes.GetAll(attrOid);
            switch (v.Count)
            {
            case 0:
                return null;
            case 1:
            {
                Asn1.Cms.Attribute t = (Asn1.Cms.Attribute)v[0];
                Asn1Set attrValues = t.AttrValues;

                if (attrValues.Count != 1)
                    throw new CmsException($"A {printableName} attribute MUST have a single attribute value");

                return attrValues[0];
            }
            default:
                throw new CmsException(
                    $"The SignedAttributes in a SignerInfo MUST NOT include multiple instances of the {printableName} attribute");
            }
        }

        private Asn1.Cms.Time GetSigningTime()
        {
            Asn1Encodable validSigningTime = GetSingleValuedSignedAttribute(CmsAttributes.SigningTime, "signing-time");
            if (validSigningTime == null)
                return null;

            try
            {
                return Asn1.Cms.Time.GetInstance(validSigningTime);
            }
            catch (ArgumentException)
            {
                throw new CmsException("signing-time attribute value not a valid 'Time' structure");
            }
        }

        /// <summary>
        /// Returns a copy of <paramref name="signerInformation"/> with unsigned attributes replaced by
        /// <paramref name="unsignedAttributes"/>.
        /// </summary>
        /// <param name="signerInformation">The signer information to copy.</param>
        /// <param name="unsignedAttributes">The replacement unsigned attributes, or null to clear them.</param>
        /// <returns>A new signer information object with the updated unsigned attributes.</returns>
        public static SignerInformation ReplaceUnsignedAttributes(SignerInformation signerInformation,
            Asn1.Cms.AttributeTable unsignedAttributes)
        {
            // TODO[cms] Any way to give control over ASN.1 encoding here?
            var newUnsignedAttrs = unsignedAttributes?.ToDerSet();

            var oldInfo = signerInformation.SignerInfo;

            var newInfo = new SignerInfo(oldInfo.SignerID, oldInfo.DigestAlgorithm, oldInfo.SignedAttrs,
                oldInfo.SignatureAlgorithm, oldInfo.Signature, newUnsignedAttrs);

            return new SignerInformation(newInfo, signerInformation.contentType, signerInformation.content, null);
        }

        /// <summary>
        /// Returns a copy of <paramref name="signerInformation"/> with counter signatures from
        /// <paramref name="counterSigners"/> attached as an unsigned attribute.
        /// </summary>
        /// <param name="signerInformation">The signer information to copy.</param>
        /// <param name="counterSigners">The counter signatures to attach.</param>
        /// <returns>A new signer information object with the counter signatures attached.</returns>
        public static SignerInformation AddCounterSigners(SignerInformation signerInformation,
            SignerInformationStore counterSigners)
        {
            // TODO Perform checks from RFC 3852 11.4

            var attrValues = DerSet.Map(counterSigners.SignersInternal, sigInf => sigInf.SignerInfo);

            var unsignedAttributes = (signerInformation.UnsignedAttributes ?? DerSet.Empty.ToAttributeTable())
                .Add(new Asn1.Cms.Attribute(CmsAttributes.CounterSignature, attrValues));

            var oldInfo = signerInformation.SignerInfo;

            var newInfo = new SignerInfo(oldInfo.SignerID, oldInfo.DigestAlgorithm, oldInfo.SignedAttrs,
                oldInfo.SignatureAlgorithm, oldInfo.Signature, unsignedAttributes.ToDerSet());

            return new SignerInformation(newInfo, signerInformation.contentType, signerInformation.content,
                calculatedDigest: null);
        }

        private static bool VerifySignature(ISigner verifier, ICipherParameters parameters, byte[] message,
            byte[] signature)
        {
            verifier.Init(false, parameters);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signature);
        }
    }
}
