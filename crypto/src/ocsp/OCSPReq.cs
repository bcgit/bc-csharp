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
    /// <summary>An OCSP request (RFC 6960), optionally signed by the requestor.</summary>
    /// <remarks>
    /// Instances can be parsed from an encoding or produced by <see cref="OcspReqGenerator"/>. The ASN.1 structure is:
    /// <code>
    /// OcspRequest     ::=     SEQUENCE {
    ///       tbsRequest                  TBSRequest,
    ///       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
    ///
    ///   TBSRequest      ::=     SEQUENCE {
    ///       version             [0]     EXPLICIT Version DEFAULT v1,
    ///       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
    ///       requestList                 SEQUENCE OF Request,
    ///       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
    ///
    ///   Signature       ::=     SEQUENCE {
    ///       signatureAlgorithm      AlgorithmIdentifier,
    ///       signature               BIT STRING,
    ///       certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
    ///
    ///   Version         ::=             INTEGER  {  v1(0) }
    ///
    ///   Request         ::=     SEQUENCE {
    ///       reqCert                     CertID,
    ///       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
    ///
    ///   CertID          ::=     SEQUENCE {
    ///       hashAlgorithm       AlgorithmIdentifier,
    ///       issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
    ///       issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
    ///       serialNumber        CertificateSerialNumber }
    /// </code>
    /// </remarks>
    public class OcspReq
        : X509ExtensionBase
    {
        private OcspRequest req;

        /// <summary>Create from an existing ASN.1 OcspRequest structure.</summary>
        /// <param name="req">The ASN.1 structure.</param>
        public OcspReq(OcspRequest req)
        {
            this.req = req;
        }

        /// <summary>Parse a request from its encoding.</summary>
        /// <param name="req">The encoded OCSP request.</param>
        /// <exception cref="IOException">The encoding is malformed.</exception>
        public OcspReq(byte[] req)
            : this(new Asn1InputStream(req))
        {
        }

        /// <summary>Parse a request from a stream containing its encoding.</summary>
        /// <param name="inStr">A stream positioned at the encoded OCSP request.</param>
        /// <exception cref="IOException">The encoding is malformed.</exception>
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
        /// <exception cref="OcspException">The tbsRequest could not be encoded.</exception>
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

        /// <summary>Gets the version of the request, as a one-based number (1 for v1).</summary>
        public int Version => req.TbsRequest.Version.IntValueExact + 1;

        /// <summary>Gets the requestor name, or null if the request does not carry one.</summary>
        public GeneralName RequestorName => GeneralName.GetInstance(req.TbsRequest.RequestorName);

        /// <summary>Return the individual certificate requests contained in this request.</summary>
        public Req[] GetRequestList() =>
            req.TbsRequest.RequestList.MapElements(element => new Req(Request.GetInstance(element)));

        /// <summary>Gets the extensions that apply to the request as a whole, or null if there are none.</summary>
        public X509Extensions RequestExtensions => X509Extensions.GetInstance(req.TbsRequest.RequestExtensions);

        /// <inheritdoc/>
        protected override X509Extensions GetX509Extensions() => RequestExtensions;

        /// <summary>Gets the signature algorithm, or null if the request is not signed.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => req.OptionalSignature?.SignatureAlgorithm;

        /// <summary>
        /// The object identifier representing the signature algorithm, or null if the request is not signed.
        /// </summary>
        public string SignatureAlgOid => req.OptionalSignature?.SignatureAlgorithm.Algorithm.GetID();

        /// <summary>Return the signature octets, or null if the request is not signed.</summary>
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

        /// <summary>
        /// If the request is signed return the certificates it carries (possibly an empty array), otherwise return
        /// null.
        /// </summary>
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
        /// <param name="publicKey">The public key of the requestor.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="OcspException">
        /// The request is unsigned, or the signature could not be processed.
        /// </exception>
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
