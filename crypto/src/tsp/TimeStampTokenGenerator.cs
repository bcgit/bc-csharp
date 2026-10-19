using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>Generator for RFC 3161 time-stamp tokens.</summary>
    /// <remarks>
    /// Configure the generator with the TSA's key, certificate and policy, optionally set the accuracy, ordering, TSA
    /// name and the certificates and CRLs to include, then call <c>Generate</c> for each request.
    /// </remarks>
    public class TimeStampTokenGenerator
    {
        private int accuracySeconds = -1;
        private int accuracyMillis = -1;
        private int accuracyMicros = -1;
        private bool ordering = false;
        private GeneralName tsa = null;
        private DerObjectIdentifier m_policy;

        private IStore<X509Certificate> x509Certs;
        private IStore<X509Crl> x509Crls;
        private IStore<X509V2AttributeCertificate> x509AttrCerts;
        private Dictionary<DerObjectIdentifier, IStore<Asn1Encodable>> otherRevoc =
            new Dictionary<DerObjectIdentifier, IStore<Asn1Encodable>>();
        private SignerInfoGenerator signerInfoGenerator;

        private Resolution resolution = Resolution.R_SECONDS;

        /// <summary>Gets or sets the resolution to which the generation time is rounded down.</summary>
        /// <remarks>The default is <see cref="Tsp.Resolution.R_SECONDS"/>.</remarks>
        public Resolution Resolution
        {
            get { return resolution; }
            set { resolution = value; }
        }

        /// <summary>Basic creation - only the default attributes will be included here.</summary>
        /// <param name="key">The TSA's private key.</param>
        /// <param name="cert">The TSA's certificate.</param>
        /// <param name="digestOID">The object identifier of the digest algorithm used for signing.</param>
        /// <param name="tsaPolicyOID">The object identifier of the default TSA policy, or null for none.</param>
        /// <exception cref="TspValidationException">The certificate is not suitable for time stamping.</exception>
        public TimeStampTokenGenerator(AsymmetricKeyParameter key, X509Certificate cert, string digestOID,
            string tsaPolicyOID)
            : this(key, cert, digestOID, tsaPolicyOID, null, null)
        {
        }

        /// <summary>Create from a signer info generator.</summary>
        /// <param name="signerInfoGen">The generator for the TSA's signature; it must have a certificate.</param>
        /// <param name="digestCalculator">The digest used to identify the TSA's certificate.</param>
        /// <param name="tsaPolicy">The default TSA policy, or null for none.</param>
        /// <param name="isIssuerSerialIncluded">Whether to include the certificate's issuer and serial number.</param>
        /// <exception cref="ArgumentException">The signer info generator has no associated certificate.</exception>
        /// <exception cref="TspValidationException">The certificate is not suitable for time stamping.</exception>
        /// <exception cref="TspException">The certificate could not be processed.</exception>
        public TimeStampTokenGenerator(SignerInfoGenerator signerInfoGen, IDigestFactory digestCalculator,
            DerObjectIdentifier tsaPolicy, bool isIssuerSerialIncluded)
        {
            this.signerInfoGenerator = signerInfoGen;
            m_policy = tsaPolicy;

            X509Certificate assocCert = signerInfoGen.Certificate ??
                throw new ArgumentException("SignerInfoGenerator must have an associated certificate");

            TspUtil.ValidateCertificate(assocCert);

            var digestAlgID = (AlgorithmIdentifier)digestCalculator.AlgorithmDetails;
            var digestAlgOid = digestAlgID.Algorithm;

            try
            {
                var certHash = DerOctetString.WithContents(
                    X509.X509Utilities.CalculateDigest(digestCalculator, assocCert.GetEncoded()));

                var issuerSerial = isIssuerSerialIncluded ? X509.X509Utilities.CreateIssuerSerial(assocCert) : null;

                CmsAttributeTableGenerator signedGen;
                if (OiwObjectIdentifiers.IdSha1.Equals(digestAlgOid))
                {
                    signedGen = new TableGen(signerInfoGen, new EssCertID(certHash, issuerSerial));
                }
                else
                {
                    // TODO Why reconstruct this? (if normalizing the parameters should use DigestAlgorithmFinder??)
                    digestAlgID = new AlgorithmIdentifier(digestAlgOid);

                    signedGen = new TableGen2(signerInfoGen, new EssCertIDv2(digestAlgID, certHash, issuerSerial));
                }

                this.signerInfoGenerator = signerInfoGen.NewBuilder()
                    .WithSignedAttributeGenerator(signedGen)
                    .Build(signerInfoGen.SignatureFactory, signerInfoGen.Certificate);
            }
            catch (Exception ex)
            {
                throw new TspException("Exception processing certificate", ex);
            }
        }

        /// <summary>Create with a signer with extra signed/unsigned attributes.</summary>
        /// <param name="key">The TSA's private key.</param>
        /// <param name="cert">The TSA's certificate.</param>
        /// <param name="digestOID">The object identifier of the digest algorithm used for signing.</param>
        /// <param name="tsaPolicyOID">The object identifier of the default TSA policy, or null for none.</param>
        /// <param name="signedAttr">Extra signed attributes, or null for none.</param>
        /// <param name="unsignedAttr">Extra unsigned attributes, or null for none.</param>
        /// <exception cref="TspValidationException">The certificate is not suitable for time stamping.</exception>
        public TimeStampTokenGenerator(AsymmetricKeyParameter key, X509Certificate cert, string digestOID,
            string tsaPolicyOID, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
            : this(
                MakeInfoGenerator(key, cert, new DerObjectIdentifier(digestOID), signedAttr, unsignedAttr),
                Asn1DigestFactory.Get(OiwObjectIdentifiers.IdSha1),
                tsaPolicyOID != null ? new DerObjectIdentifier(tsaPolicyOID) : null,
                false)
        {
        }

        internal static SignerInfoGenerator MakeInfoGenerator(AsymmetricKeyParameter key, X509Certificate cert,
            DerObjectIdentifier digestOid, Asn1.Cms.AttributeTable signedAttr, Asn1.Cms.AttributeTable unsignedAttr)
        {
            TspUtil.ValidateCertificate(cert);

            //
            // Add the ESSCertID attribute
            //
            IDictionary<DerObjectIdentifier, object> signedAttrs;
            if (signedAttr != null)
            {
                signedAttrs = signedAttr.ToDictionary();
            }
            else
            {
                signedAttrs = new Dictionary<DerObjectIdentifier, object>();
            }

            string digestName = CmsSignedHelper.GetDigestAlgName(digestOid);
            DerObjectIdentifier encOid = CmsSignedHelper.GetEncOid(key, digestOid.Id);
            string signatureName = digestName + "with" + CmsSignedHelper.GetEncryptionAlgName(encOid);
            var contentSigner = new Asn1SignatureFactory(signatureName, key);

            var signedGen = new DefaultSignedAttributeTableGenerator(new Asn1.Cms.AttributeTable(signedAttrs));
            var unsignedGen = new SimpleAttributeTableGenerator(unsignedAttr);

            return new SignerInfoGeneratorBuilder()
                .WithSignedAttributeGenerator(signedGen)
                .WithUnsignedAttributeGenerator(unsignedGen)
                .Build(contentSigner, cert);
        }

        /// <summary>Set the attribute certificates to include when the request asks for certificates.</summary>
        public void SetAttributeCertificates(IStore<X509V2AttributeCertificate> attributeCertificates)
        {
            this.x509AttrCerts = attributeCertificates;
        }

        /// <summary>Set the certificates to include when the request asks for certificates.</summary>
        public void SetCertificates(IStore<X509Certificate> certificates)
        {
            this.x509Certs = certificates;
        }

        /// <summary>Set the CRLs to include in every token.</summary>
        public void SetCrls(IStore<X509Crl> crls)
        {
            this.x509Crls = crls;
        }

        /// <summary>Add other revocation information, in the given format, to include in every token.</summary>
        public void AddOtherRevocationInfos(DerObjectIdentifier otherRevInfoFormat,
            IStore<Asn1Encodable> otherRevInfoStore)
        {
            otherRevoc[otherRevInfoFormat] = otherRevInfoStore;
        }

        /// <summary>Set the seconds component of the accuracy; a value of zero or less leaves it out.</summary>
        public void SetAccuracySeconds(
            int accuracySeconds)
        {
            this.accuracySeconds = accuracySeconds;
        }

        /// <summary>Set the milliseconds component of the accuracy; a value of zero or less leaves it out.</summary>
        public void SetAccuracyMillis(
            int accuracyMillis)
        {
            this.accuracyMillis = accuracyMillis;
        }

        /// <summary>Set the microseconds component of the accuracy; a value of zero or less leaves it out.</summary>
        public void SetAccuracyMicros(
            int accuracyMicros)
        {
            this.accuracyMicros = accuracyMicros;
        }

        /// <summary>Set whether tokens from this TSA can be ordered by their generation time alone.</summary>
        public void SetOrdering(
            bool ordering)
        {
            this.ordering = ordering;
        }

        /// <summary>Set the name of the TSA to be included in the tokens.</summary>
        public void SetTsa(
            GeneralName tsa)
        {
            this.tsa = tsa;
        }

        /// <summary>Generate a time-stamp token for the given request.</summary>
        /// <param name="request">The request to respond to.</param>
        /// <param name="serialNumber">The serial number of the token.</param>
        /// <param name="genTime">The generation time of the token.</param>
        /// <returns>The <see cref="TimeStampToken"/>.</returns>
        /// <exception cref="TspValidationException">No policy is specified by the request or generator.</exception>
        /// <exception cref="TspException">The token could not be generated.</exception>
        public TimeStampToken Generate(TimeStampRequest request, BigInteger serialNumber, DateTime genTime) =>
            Generate(request, serialNumber, genTime, null);

        /// <summary>Generate a time-stamp token for the given request, with additional extensions.</summary>
        /// <param name="request">The request to respond to.</param>
        /// <param name="serialNumber">The serial number of the token.</param>
        /// <param name="genTime">The generation time of the token.</param>
        /// <param name="additionalExtensions">Extensions to add to those in the request, or null for none.</param>
        /// <returns>The <see cref="TimeStampToken"/>.</returns>
        /// <exception cref="TspValidationException">No policy is specified by the request or generator.</exception>
        /// <exception cref="TspException">The token could not be generated.</exception>
        public TimeStampToken Generate(TimeStampRequest request, BigInteger serialNumber, DateTime genTime,
            X509Extensions additionalExtensions)
        {
            Accuracy accuracy = null;
            if (accuracySeconds > 0 || accuracyMillis > 0 || accuracyMicros > 0)
            {
                DerInteger seconds = null;
                if (accuracySeconds > 0)
                {
                    seconds = DerInteger.ValueOf(accuracySeconds);
                }

                DerInteger millis = null;
                if (accuracyMillis > 0)
                {
                    millis = DerInteger.ValueOf(accuracyMillis);
                }

                DerInteger micros = null;
                if (accuracyMicros > 0)
                {
                    micros = DerInteger.ValueOf(accuracyMicros);
                }

                accuracy = new Accuracy(seconds, millis, micros);
            }

            DerBoolean derOrdering = null;
            if (ordering)
            {
                derOrdering = DerBoolean.GetInstance(ordering);
            }

            var timeStampReq = request.TimeStampReq;

            MessageImprint messageImprint = timeStampReq.MessageImprint;

            DerInteger nonce = timeStampReq.Nonce;

            DerObjectIdentifier policy = timeStampReq.ReqPolicy ?? m_policy
                ?? throw new TspValidationException("request contains no policy", PkiFailureInfo.UnacceptedPolicy);

            X509Extensions respExtensions = request.Extensions;
            if (additionalExtensions != null)
            {
                X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();

                if (respExtensions != null)
                {
                    foreach(var oid in respExtensions.ExtensionOids)
                    {
                        extGen.AddExtension(oid, respExtensions.GetExtension(oid));
                    }
                }

                foreach (var oid in additionalExtensions.ExtensionOids)
                {
                    extGen.AddExtension(oid, additionalExtensions.GetExtension(oid));
                }

                respExtensions = extGen.Generate();
            }

            /*
             * RFC 3161. The ASN.1 GeneralizedTime syntax can include fraction-of-second details. Such syntax, without
             * the restrictions from RFC 2459 Section 4.1.2.5.2, where GeneralizedTime is limited to represent the
             * time with a granularity of one second, may be used here.
             */
            var timeStampTime = new DerGeneralizedTime(TspUtil.WithResolution(genTime, resolution));

            TstInfo tstInfo = new TstInfo(policy, messageImprint,
                new DerInteger(serialNumber), timeStampTime, accuracy,
                derOrdering, nonce, tsa, respExtensions);

            try
            {
                CmsSignedDataGenerator signedDataGenerator = new CmsSignedDataGenerator();

                byte[] derEncodedTstInfo = tstInfo.GetDerEncoded();

                if (request.CertReq)
                {
                    signedDataGenerator.AddCertificates(x509Certs);
                    signedDataGenerator.AddAttributeCertificates(x509AttrCerts);
                }

                signedDataGenerator.AddCrls(x509Crls);

                foreach (KeyValuePair<DerObjectIdentifier, IStore<Asn1Encodable>> entry in otherRevoc)
                {
                    signedDataGenerator.AddOtherRevocationInfos(
                        otherRevInfoFormat: entry.Key,
                        otherRevInfoStore: entry.Value);
                }

                signedDataGenerator.AddSignerInfoGenerator(signerInfoGenerator);

                CmsSignedData signedData = signedDataGenerator.Generate(
                    new CmsProcessableByteArray(PkcsObjectIdentifiers.IdCTTstInfo, derEncodedTstInfo),
                    encapsulate: true);

                return new TimeStampToken(signedData);
            }
            catch (CmsException cmsEx)
            {
                throw new TspException("Error generating time-stamp token", cmsEx);
            }
            catch (IOException e)
            {
                throw new TspException("Exception encoding info", e);
            }
        }

        private class TableGen
            : CmsAttributeTableGenerator
        {
            private readonly SignerInfoGenerator infoGen;
            private readonly EssCertID essCertID;

            internal TableGen(SignerInfoGenerator infoGen, EssCertID essCertID)
            {
                this.infoGen = infoGen;
                this.essCertID = essCertID;
            }

            public Asn1.Cms.AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
            {
                Asn1.Cms.AttributeTable tab = infoGen.SignedAttributeTableGenerator.GetAttributes(parameters);
                if (tab.HasAny(PkcsObjectIdentifiers.IdAASigningCertificate))
                    return tab;

                return tab.Add(PkcsObjectIdentifiers.IdAASigningCertificate, new SigningCertificate(essCertID));
            }
        }

        private class TableGen2
            : CmsAttributeTableGenerator
        {
            private readonly SignerInfoGenerator infoGen;
            private readonly EssCertIDv2 essCertIDv2;

            internal TableGen2(SignerInfoGenerator infoGen, EssCertIDv2 essCertIDv2)
            {
                this.infoGen = infoGen;
                this.essCertIDv2 = essCertIDv2;
            }

            public Asn1.Cms.AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
            {
                Asn1.Cms.AttributeTable tab = infoGen.SignedAttributeTableGenerator.GetAttributes(parameters);
                if (tab.HasAny(PkcsObjectIdentifiers.IdAASigningCertificateV2))
                    return tab;

                return tab.Add(PkcsObjectIdentifiers.IdAASigningCertificateV2, new SigningCertificateV2(essCertIDv2));
            }
        }
    }
}
