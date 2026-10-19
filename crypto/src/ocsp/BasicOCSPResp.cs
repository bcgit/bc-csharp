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
    /// <summary>The basic OCSP response (RFC 6960), signed by the responder.</summary>
    /// <remarks>
    /// Instances can be produced by <see cref="BasicOcspRespGenerator"/> or obtained from
    /// <see cref="OcspResp.GetResponseObject"/>. The ASN.1 structure is:
    /// <code>
    /// BasicOcspResponse ::= SEQUENCE {
    ///     tbsResponseData     ResponseData,
    ///     signatureAlgorithm  AlgorithmIdentifier,
    ///     signature           BIT STRING,
    ///     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class BasicOcspResp
        : X509ExtensionBase
    {
        private readonly BasicOcspResponse resp;
        private readonly ResponseData data;
        //private readonly X509Certificate[] chain;

        /// <summary>Create from an existing ASN.1 BasicOcspResponse structure.</summary>
        /// <param name="resp">The ASN.1 structure.</param>
        public BasicOcspResp(BasicOcspResponse resp)
        {
            this.resp = resp;
            this.data = resp.TbsResponseData;
        }

        /// <returns>The DER encoding of the tbsResponseData field.</returns>
        /// <exception cref="OcspException">In the event of an encoding error.</exception>
        public byte[] GetTbsResponseData()
        {
            try
            {
                return data.GetEncoded(Asn1Encodable.Der);
            }
            catch (IOException e)
            {
                throw new OcspException("problem encoding tbsResponseData", e);
            }
        }

        /// <summary>Gets the version of the response data, as a one-based number (1 for v1).</summary>
        public int Version => data.Version.IntValueExact + 1;

        /// <summary>Gets the identifier of the responder that produced this response.</summary>
        public RespID ResponderId => new RespID(data.ResponderID);

        /// <summary>Gets the time at which the responder signed this response.</summary>
        public DateTime ProducedAt => data.ProducedAt.ToDateTime();

        /// <summary>Gets the individual certificate status responses.</summary>
        public SingleResp[] Responses =>
            data.Responses.MapElements(element => new SingleResp(SingleResponse.GetInstance(element)));

        /// <summary>Gets the extensions that apply to the response as a whole, or null if there are none.</summary>
        public X509Extensions ResponseExtensions => data.ResponseExtensions;

        /// <inheritdoc/>
        protected override X509Extensions GetX509Extensions() => ResponseExtensions;

        /// <summary>Gets the signature alg name.</summary>
        [Obsolete("Will be removed")]
        public string SignatureAlgName => X509SignatureUtilities.GetSignatureName(SignatureAlgorithm);

        /// <summary>Gets the algorithm identifier of the signature on this response.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => resp.SignatureAlgorithm;

        /// <summary>Gets the signature alg oid.</summary>
        [Obsolete("Will be removed")]
        public string SignatureAlgOid => resp.SignatureAlgorithm.Algorithm.GetID();

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignature() => resp.GetSignatureOctets();

        private List<X509Certificate> GetCertList()
        {
            // load the certificates if we have any

            var result = new List<X509Certificate>();

            Asn1Sequence certs = resp.Certs;
            if (certs != null)
            {
                foreach (Asn1Encodable element in certs)
                {
                    result.Add(new X509Certificate(X509CertificateStructure.GetInstance(element)));
                }
            }

            return result;
        }

        /// <summary>Return the certificates, if any, carried in the response (possibly an empty array).</summary>
        public X509Certificate[] GetCerts() => GetCertList().ToArray();

        /// <returns>The certificates, if any, associated with the response.</returns>
        /// <exception cref="OcspException">In the event of an encoding error.</exception>
        public IStore<X509Certificate> GetCertificates() => CollectionUtilities.CreateStore(GetCertList());

        /// <summary>
        /// Verify the signature against the tbsResponseData object we contain.
        /// </summary>
        /// <param name="publicKey">The public key of the responder.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="OcspException">The signature could not be processed.</exception>
        public bool Verify(AsymmetricKeyParameter publicKey)
        {
            try
            {
                var verifierFactory = new Asn1VerifierFactory(resp.SignatureAlgorithm, publicKey);

                return X509.X509Utilities.VerifySignature(verifierFactory, data, resp.Signature);
            }
            catch (Exception e)
            {
                throw new OcspException("exception processing sig", e);
            }
        }

        /// <returns>The ASN.1 encoded representation of this object.</returns>
        public byte[] GetEncoded() => resp.GetEncoded();

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is BasicOcspResp that
                && this.resp.Equals(that.resp);
        }

        /// <inheritdoc/>
        public override int GetHashCode() => resp.GetHashCode();
    }
}
