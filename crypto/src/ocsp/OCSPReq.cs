using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /**
     * <pre>
     * OcspRequest     ::=     SEQUENCE {
     *       tbsRequest                  TBSRequest,
     *       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
     *
     *   TBSRequest      ::=     SEQUENCE {
     *       version             [0]     EXPLICIT Version DEFAULT v1,
     *       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
     *       requestList                 SEQUENCE OF Request,
     *       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
     *
     *   Signature       ::=     SEQUENCE {
     *       signatureAlgorithm      AlgorithmIdentifier,
     *       signature               BIT STRING,
     *       certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
     *
     *   Version         ::=             INTEGER  {  v1(0) }
     *
     *   Request         ::=     SEQUENCE {
     *       reqCert                     CertID,
     *       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
     *
     *   CertID          ::=     SEQUENCE {
     *       hashAlgorithm       AlgorithmIdentifier,
     *       issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
     *       issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
     *       serialNumber        CertificateSerialNumber }
     * </pre>
     */
    public class OcspReq
        : X509ExtensionBase
    {
        private OcspRequest req;

        public OcspReq(OcspRequest req)
        {
            this.req = req;
        }

        public OcspReq(byte[] req)
            : this(new Asn1InputStream(req))
        {
        }

        public OcspReq(Stream inStr)
            : this(new Asn1InputStream(inStr))
        {
        }

        private OcspReq(Asn1InputStream aIn)
        {
            try
            {
                this.req = OcspRequest.GetInstance(aIn.ReadObject());
            }
            catch (ArgumentException e)
            {
                throw new IOException("malformed request: " + e.Message);
            }
            catch (InvalidCastException e)
            {
                throw new IOException("malformed request: " + e.Message);
            }
        }

        /// <summary>Return the DER encoding of the tbsRequest field.</summary>
        public byte[] GetTbsRequest()
        {
            try
            {
                return req.TbsRequest.GetEncoded(Asn1Encodable.Der);
            }
            catch (IOException e)
            {
                throw new OcspException("problem encoding tbsRequest", e);
            }
        }

        public int Version => req.TbsRequest.Version.IntValueExact + 1;

        public GeneralName RequestorName => GeneralName.GetInstance(req.TbsRequest.RequestorName);

        public Req[] GetRequestList() =>
            req.TbsRequest.RequestList.MapElements(element => new Req(Request.GetInstance(element)));

        public X509Extensions RequestExtensions => X509Extensions.GetInstance(req.TbsRequest.RequestExtensions);

        protected override X509Extensions GetX509Extensions() => RequestExtensions;

        public AlgorithmIdentifier SignatureAlgorithm => req.OptionalSignature?.SignatureAlgorithm;

        /// <summary>The object identifier representing the signature algorithm.</summary>
        public string SignatureAlgOid => req.OptionalSignature?.SignatureAlgorithm.Algorithm.GetID();

        public byte[] GetSignature() => req.OptionalSignature?.GetSignatureOctets();

        private List<X509Certificate> GetCertList()
        {
            // load the certificates if we have any

            var result = new List<X509Certificate>();

            Asn1Sequence certs = req.OptionalSignature.Certs;
            if (certs != null)
            {
                foreach (Asn1Encodable element in certs)
                {
                    result.Add(new X509Certificate(X509CertificateStructure.GetInstance(element)));
                }
            }

            return result;
        }

        public X509Certificate[] GetCerts()
        {
            if (!IsSigned)
                return null;

            return GetCertList().ToArray();
        }

        /// <summary>
        /// If the request is signed return a possibly empty CertStore containing the certificates in the
        /// request. If the request is not signed the method returns null.
        /// </summary>
        public IStore<X509Certificate> GetCertificates()
        {
            if (!IsSigned)
                return null;

            return CollectionUtilities.CreateStore(GetCertList());
        }

        /// <summary>Return whether or not this request is signed.</summary>
        public bool IsSigned => req.OptionalSignature != null;

        /// <summary>Verify the signature against the TBSRequest object we contain.</summary>
        public bool Verify(AsymmetricKeyParameter publicKey)
        {
            var optionalSignature = req.OptionalSignature;
            if (optionalSignature == null)
                throw new OcspException("attempt to verify signature on unsigned object");

            try
            {
                var verifierFactory = new Asn1VerifierFactory(optionalSignature.SignatureAlgorithm, publicKey);

                return X509.X509Utilities.VerifySignature(verifierFactory, req.TbsRequest,
                    optionalSignature.SignatureValue);
            }
            catch (Exception e)
            {
                throw new OcspException("exception processing sig: " + e, e);
            }
        }

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => req.GetEncoded();
    }
}
