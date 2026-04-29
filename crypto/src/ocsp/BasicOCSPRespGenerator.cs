using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Generator for basic OCSP response objects.</summary>
    public class BasicOcspRespGenerator
    {
        private readonly List<ResponseObject> m_list = new List<ResponseObject>();

        private X509Extensions m_responseExtensions;
        private RespID m_responderID;

        private class ResponseObject
        {
            internal CertificateID certId;
            internal CertStatus certStatus;
            internal DerGeneralizedTime thisUpdate;
            internal DerGeneralizedTime nextUpdate;
            internal X509Extensions extensions;

            internal ResponseObject(
                CertificateID certId,
                CertificateStatus certStatus,
                DateTime thisUpdate,
                DateTime? nextUpdate,
                X509Extensions extensions)
            {
                this.certId = certId;

                if (certStatus == null)
                {
                    this.certStatus = new CertStatus();
                }
                else if (certStatus is UnknownStatus)
                {
                    this.certStatus = new CertStatus(2, DerNull.Instance);
                }
                else
                {
                    RevokedStatus rs = (RevokedStatus)certStatus;
                    CrlReason revocationReason = rs.HasRevocationReason
                        ? new CrlReason(rs.RevocationReason)
                        : null;

                    var revocationTime = Rfc5280Asn1Utilities.CreateGeneralizedTime(rs.RevocationTime);
                    var revokedInfo = new RevokedInfo(revocationTime, revocationReason);

                    this.certStatus = new CertStatus(revokedInfo);
                }

                this.thisUpdate = Rfc5280Asn1Utilities.CreateGeneralizedTime(thisUpdate);
                this.nextUpdate = nextUpdate.HasValue ? Rfc5280Asn1Utilities.CreateGeneralizedTime(nextUpdate.Value) : null;

                this.extensions = extensions;
            }

            public SingleResponse ToResponse()
            {
                return new SingleResponse(certId.ToAsn1Object(), certStatus, thisUpdate, nextUpdate, extensions);
            }
        }

        /// <summary>Basic constructor.</summary>
        public BasicOcspRespGenerator(RespID responderID)
        {
            m_responderID = responderID;
        }

        /// <summary>Construct with the responderID as the SHA-1 keyHash of the passed in public key.</summary>
        public BasicOcspRespGenerator(AsymmetricKeyParameter publicKey)
        {
            m_responderID = new RespID(publicKey);
        }

        /// <summary>Add a response for a particular Certificate ID.</summary>
        /// <param name="certID">Certificate ID details.</param>
        /// <param name="certStatus">Status of the certificate - null if okay.</param>
        public void AddResponse(CertificateID certID, CertificateStatus certStatus)
        {
            m_list.Add(new ResponseObject(certID, certStatus, DateTime.UtcNow, null, null));
        }

        /// <summary>Add a response for a particular Certificate ID.</summary>
        /// <param name="certID">Certificate ID details.</param>
        /// <param name="certStatus">Status of the certificate - null if okay.</param>
        /// <param name="singleExtensions">Optional extensions.</param>
        public void AddResponse(CertificateID certID, CertificateStatus certStatus, X509Extensions singleExtensions)
        {
            m_list.Add(new ResponseObject(certID, certStatus, DateTime.UtcNow, null, singleExtensions));
        }

        /// <summary>Add a response for a particular Certificate ID.</summary>
        /// <param name="certID">Certificate ID details.</param>
        /// <param name="nextUpdate">The date when next update should be requested.</param>
        /// <param name="certStatus">Status of the certificate - null if okay.</param>
        /// <param name="singleExtensions">Optional extensions.</param>
        public void AddResponse(CertificateID certID, CertificateStatus certStatus, DateTime? nextUpdate,
            X509Extensions singleExtensions)
        {
            m_list.Add(new ResponseObject(certID, certStatus, DateTime.UtcNow, nextUpdate, singleExtensions));
        }

        /// <summary>Add a response for a particular Certificate ID.</summary>
        /// <param name="certID">Certificate ID details.</param>
        /// <param name="thisUpdate">The date this response was valid on.</param>
        /// <param name="nextUpdate">The date when next update should be requested.</param>
        /// <param name="certStatus">Status of the certificate - null if okay.</param>
        /// <param name="singleExtensions">Optional extensions.</param>
        public void AddResponse(CertificateID certID, CertificateStatus certStatus, DateTime thisUpdate,
            DateTime? nextUpdate, X509Extensions singleExtensions)
        {
            m_list.Add(new ResponseObject(certID, certStatus, thisUpdate, nextUpdate, singleExtensions));
        }

        /// <summary>Set the extensions for the response.</summary>
        public void SetResponseExtensions(X509Extensions responseExtensions)
        {
            m_responseExtensions = responseExtensions;
        }

        private BasicOcspResp GenerateResponse(ISignatureFactory signatureFactory, X509Certificate[] chain,
            DateTime producedAt)
        {
            AlgorithmIdentifier sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

            DerSequence responses;
            try
            {
                responses = DerSequence.Map(m_list, ro => ro.ToResponse());
            }
            catch (Exception e)
            {
                throw new OcspException("exception creating Request", e);
            }

            var responseData = new ResponseData(m_responderID.ToAsn1Object(),
                Rfc5280Asn1Utilities.CreateGeneralizedTime(producedAt), responses, m_responseExtensions);

            DerBitString signature;
            try
            {
                signature = X509.X509Utilities.GenerateSignature(signatureFactory, responseData);
            }
            catch (Exception e)
            {
                throw new OcspException("exception processing ResponseData", e);
            }

            DerSequence certs = null;
            if (!Arrays.IsNullOrEmpty(chain))
            {
                certs = DerSequence.Map(chain, c => c.CertificateStructure);
            }

            return new BasicOcspResp(new BasicOcspResponse(responseData, sigAlgID, signature, certs));
        }

        // TODO[api] Rename 'thisUpdate' to 'producedAt'
        public BasicOcspResp Generate(string signingAlgorithm, AsymmetricKeyParameter privateKey,
            X509Certificate[] chain, DateTime thisUpdate)
        {
            return Generate(signingAlgorithm, privateKey, chain, thisUpdate, null);
        }

        public BasicOcspResp Generate(string signingAlgorithm, AsymmetricKeyParameter privateKey,
            X509Certificate[] chain, DateTime producedAt, SecureRandom random)
        {
            if (signingAlgorithm == null)
                throw new ArgumentNullException(nameof(signingAlgorithm));

            return GenerateResponse(new Asn1SignatureFactory(signingAlgorithm, privateKey, random), chain, producedAt);
        }

        /// <summary>
        /// Generate the signed response using the passed in signature calculator.
        /// </summary>
        /// <param name="signatureCalculatorFactory">Implementation of signing calculator factory.</param>
        /// <param name="chain">The certificate chain associated with the response signer.</param>
        /// <param name="producedAt">"produced at" date.</param>
        /// <returns></returns>
        // TODO[api] Rename 'signatureCalculatorFactory' to 'signatureFactory'
        public BasicOcspResp Generate(ISignatureFactory signatureCalculatorFactory, X509Certificate[] chain,
            DateTime producedAt)
        {
            if (signatureCalculatorFactory == null)
                throw new ArgumentNullException(nameof(signatureCalculatorFactory));

            return GenerateResponse(signatureCalculatorFactory, chain, producedAt);
        }

        /// <summary>Return an IEnumerable of the signature names supported by the generator.</summary>
        public IEnumerable<string> SignatureAlgNames => Asn1SignatureFactory.SignatureAlgNames;
    }
}
