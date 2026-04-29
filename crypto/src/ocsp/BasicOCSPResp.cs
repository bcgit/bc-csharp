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
    /// <remarks>
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
        //private readonly X509Certificate[]	chain;

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

        public int Version => data.Version.IntValueExact + 1;

        public RespID ResponderId => new RespID(data.ResponderID);

        public DateTime ProducedAt => data.ProducedAt.ToDateTime();

        public SingleResp[] Responses =>
            data.Responses.MapElements(element => new SingleResp(SingleResponse.GetInstance(element)));

        public X509Extensions ResponseExtensions => data.ResponseExtensions;

        protected override X509Extensions GetX509Extensions() => ResponseExtensions;

        [Obsolete("Will be removed")]
        public string SignatureAlgName => X509SignatureUtilities.GetSignatureName(SignatureAlgorithm);

        public AlgorithmIdentifier SignatureAlgorithm => resp.SignatureAlgorithm;

        [Obsolete("Will be removed")]
        public string SignatureAlgOid => resp.SignatureAlgorithm.Algorithm.GetID();

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

        public X509Certificate[] GetCerts() => GetCertList().ToArray();

        /// <returns>The certificates, if any, associated with the response.</returns>
        /// <exception cref="OcspException">In the event of an encoding error.</exception>
        public IStore<X509Certificate> GetCertificates() => CollectionUtilities.CreateStore(GetCertList());

        /// <summary>
        /// Verify the signature against the tbsResponseData object we contain.
        /// </summary>
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

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is BasicOcspResp that
                && this.resp.Equals(that.resp);
        }

        public override int GetHashCode() => resp.GetHashCode();
    }
}
