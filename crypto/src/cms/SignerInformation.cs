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
    /**
     * an expanded SignerInfo block from a CMS Signed message
     */
    public class SignerInformation
    {
        private SignerID sid;

        private CmsProcessable content;
        private byte[] signature;
        private DerObjectIdentifier contentType;
        private byte[] calculatedDigest;
        private byte[] resultDigest;

        // Derived
        private Asn1.Cms.AttributeTable signedAttributeTable;
        private Asn1.Cms.AttributeTable unsignedAttributeTable;
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

        /**
         * Protected constructor. In some cases clients have their own idea about how to encode
         * the signed attributes and calculate the signature. This constructor is to allow developers
         * to deal with that by extending off the class and overriding e.g. SignedAttributes property.
         *
         * @param baseInfo the SignerInformation to base this one on.
         */
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
            this.signedAttributeTable = baseInfo.signedAttributeTable;
            this.unsignedAttributeTable = baseInfo.unsignedAttributeTable;
        }

        public bool IsCounterSignature => isCounterSignature;

        public DerObjectIdentifier ContentType => contentType;

        public SignerID SignerID => sid;

        /**
         * return the version number for this objects underlying SignerInfo structure.
         */
        public int Version => info.Version.IntValueExact;

        // TODO[api] Rename to DigestAlgorithm (after field made non-visible and/or renamed)
        public AlgorithmIdentifier DigestAlgorithmID => digestAlgorithm;

        /**
         * return the object identifier for the signature.
         */
        [Obsolete("Use 'DigestAlgorithmID' instead")]
        public string DigestAlgOid => digestAlgorithm.Algorithm.GetID();

        /**
         * return the signature parameters, or null if there aren't any.
         */
        [Obsolete("Use 'DigestAlgorithmID' instead")]
        public Asn1Object DigestAlgParams => digestAlgorithm.Parameters?.ToAsn1Object();

        /**
         * return the content digest that was calculated during verification.
         */
        public byte[] GetContentDigest()
        {
            if (resultDigest == null)
                throw new InvalidOperationException("method can only be called after verify.");

            return (byte[])resultDigest.Clone();
        }

        [Obsolete("Use 'SignatureAlgorithm' property instead")]
        public AlgorithmIdentifier EncryptionAlgorithmID => encryptionAlgorithm;

        [Obsolete("Use 'SignatureAlgorithm' property instead")]
        public string EncryptionAlgOid => encryptionAlgorithm.Algorithm.Id;

        [Obsolete("Use 'SignatureAlgorithm' property instead")]
        public Asn1Object EncryptionAlgParams => encryptionAlgorithm.Parameters?.ToAsn1Object();

        public AlgorithmIdentifier SignatureAlgorithm => encryptionAlgorithm;

        /**
         * return a table of the signed attributes - indexed by
         * the OID of the attribute.
         */
        public Asn1.Cms.AttributeTable SignedAttributes
        {
            get
            {
                if (signedAttributeTable == null)
                {
                    signedAttributeTable = signedAttributeSet?.ToAttributeTable();
                }
                return signedAttributeTable;
            }
        }

        public SignerInfo SignerInfo => info;

        [Obsolete("Use 'SignerInfo' property instead")]
        public SignerInfo ToSignerInfo() => info;

        /**
         * return a table of the unsigned attributes indexed by
         * the OID of the attribute.
         */
        public Asn1.Cms.AttributeTable UnsignedAttributes
        {
            get
            {
                if (unsignedAttributeTable == null)
                {
                    unsignedAttributeTable = unsignedAttributeSet?.ToAttributeTable();
                }
                return unsignedAttributeTable;
            }
        }

        /**
         * return the encoded signature
         */
        public byte[] GetSignature() => Arrays.Clone(signature);

        /**
         * Return a SignerInformationStore containing the counter signatures attached to this
         * signer. If no counter signatures are present an empty store is returned.
         */
        public SignerInformationStore GetCounterSignatures()
        {
            // TODO There are several checks implied by the RFC3852 comments that are missing

            /*
             * The countersignature attribute MUST be an unsigned attribute; it MUST
             * NOT be a signed attribute, an authenticated attribute, an
             * unauthenticated attribute, or an unprotected attribute.
             */
            Asn1.Cms.AttributeTable unsignedAttributeTable = UnsignedAttributes;
            if (unsignedAttributeTable == null)
                return new SignerInformationStore(new List<SignerInformation>(0));

            var counterSignatures = new List<SignerInformation>();

            /*
             * The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
             * UnsignedAttributes in a signerInfo may include multiple instances of
             * the countersignature attribute.
             */
            Asn1EncodableVector allCSAttrs = unsignedAttributeTable.GetAll(CmsAttributes.CounterSignature);

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

        /**
         * return the DER encoding of the signed attributes.
         * @throws IOException if an encoding error occurs.
         */
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
            {
                Asn1Object validContentType = GetSingleValuedSignedAttribute(
                    CmsAttributes.ContentType, "content-type");
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

            // RFC 3852 11.2 Check the message-digest attribute is correct
            {
                Asn1Object validMessageDigest = GetSingleValuedSignedAttribute(
                    CmsAttributes.MessageDigest, "message-digest");
                if (validMessageDigest == null)
                {
                    if (signedAttributeSet != null)
                        throw new CmsException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                }
                else
                {
                    if (!(validMessageDigest is Asn1OctetString signedMessageDigest))
                        throw new CmsException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");

                    if (!Arrays.AreEqual(resultDigest, signedMessageDigest.GetOctets()))
                        throw new CmsException("message-digest attribute value does not match calculated value");
                }
            }

            // RFC 3852 11.4 Validate countersignature attribute(s)
            {
                Asn1.Cms.AttributeTable signedAttrTable = this.SignedAttributes;
                if (signedAttrTable != null
                    && signedAttrTable.GetAll(CmsAttributes.CounterSignature).Count > 0)
                {
                    throw new CmsException("A countersignature attribute MUST NOT be a signed attribute");
                }

                Asn1.Cms.AttributeTable unsignedAttrTable = this.UnsignedAttributes;
                if (unsignedAttrTable != null)
                {
                    foreach (Asn1.Cms.Attribute csAttr in unsignedAttrTable.GetAll(CmsAttributes.CounterSignature))
                    {
                        if (csAttr.AttrValues.Count < 1)
                            throw new CmsException("A countersignature attribute MUST contain at least one AttributeValue");

                        // Note: We don't recursively validate the countersignature value
                    }
                }
            }

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

        /**
         * verify that the given public key successfully handles and confirms the
         * signature associated with this signer.
         */
        public bool Verify(AsymmetricKeyParameter pubKey)
        {
            if (pubKey.IsPrivate)
                throw new ArgumentException("Expected public key", nameof(pubKey));

            // Optional, but still need to validate if present
            GetSigningTime();

            return DoVerify(pubKey);
        }

        /**
         * verify that the given certificate successfully handles and confirms
         * the signature associated with this signer and, if a signingTime
         * attribute is available, that the certificate was valid at the time the
         * signature was generated.
         */
        public bool Verify(X509Certificate cert)
        {
            Asn1.Cms.Time signingTime = GetSigningTime();
            if (signingTime != null)
            {
                cert.CheckValidity(signingTime.ToDateTime());
            }

            return DoVerify(cert.GetPublicKey());
        }

        private Asn1Object GetSingleValuedSignedAttribute(DerObjectIdentifier attrOid, string printableName)
        {
            Asn1.Cms.AttributeTable unsignedAttrTable = this.UnsignedAttributes;
            if (unsignedAttrTable != null
                && unsignedAttrTable.GetAll(attrOid).Count > 0)
            {
                throw new CmsException("The " + printableName
                    + " attribute MUST NOT be an unsigned attribute");
            }

            Asn1.Cms.AttributeTable signedAttrTable = this.SignedAttributes;
            if (signedAttrTable == null)
                return null;

            Asn1EncodableVector v = signedAttrTable.GetAll(attrOid);
            switch (v.Count)
            {
            case 0:
                return null;
            case 1:
            {
                Asn1.Cms.Attribute t = (Asn1.Cms.Attribute)v[0];
                Asn1Set attrValues = t.AttrValues;

                if (attrValues.Count != 1)
                    throw new CmsException("A " + printableName + " attribute MUST have a single attribute value");

                return attrValues[0].ToAsn1Object();
            }
            default:
                throw new CmsException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
                    + printableName + " attribute");
            }
        }

        private Asn1.Cms.Time GetSigningTime()
        {
            Asn1Object validSigningTime = GetSingleValuedSignedAttribute(CmsAttributes.SigningTime, "signing-time");

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

        /**
         * Return a signer information object with the passed in unsigned
         * attributes replacing the ones that are current associated with
         * the object passed in.
         *
         * @param signerInformation the signerInfo to be used as the basis.
         * @param unsignedAttributes the unsigned attributes to add.
         * @return a copy of the original SignerInformationObject with the changed attributes.
         */
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

        /**
         * Return a signer information object with passed in SignerInformationStore representing counter
         * signatures attached as an unsigned attribute.
         *
         * @param signerInformation the signerInfo to be used as the basis.
         * @param counterSigners signer info objects carrying counter signature.
         * @return a copy of the original SignerInformationObject with the changed attributes.
         */
        public static SignerInformation AddCounterSigners(SignerInformation signerInformation,
            SignerInformationStore counterSigners)
        {
            // TODO Perform checks from RFC 3852 11.4

            var attrValues = DerSet.Map(counterSigners.SignersInternal, sigInf => sigInf.SignerInfo);

            var attributeTable = (signerInformation.UnsignedAttributes ?? DerSet.Empty.ToAttributeTable())
                .Add(new Asn1.Cms.Attribute(CmsAttributes.CounterSignature, attrValues));

            var newUnsignedAttrs = attributeTable.ToDerSet();

            var oldInfo = signerInformation.SignerInfo;

            var newInfo = new SignerInfo(oldInfo.SignerID, oldInfo.DigestAlgorithm, oldInfo.SignedAttrs,
                oldInfo.SignatureAlgorithm, oldInfo.Signature, newUnsignedAttrs);

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
