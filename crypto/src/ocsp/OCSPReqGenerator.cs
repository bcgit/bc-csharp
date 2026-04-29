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
    public class OcspReqGenerator
    {
        private readonly List<RequestObject> m_list = new List<RequestObject>();

        private GeneralName m_requestorName = null;
        private X509Extensions m_requestExtensions = null;

        private class RequestObject
        {
            internal CertificateID certId;
            internal X509Extensions extensions;

            public RequestObject(
                CertificateID certId,
                X509Extensions extensions)
            {
                this.certId = certId;
                this.extensions = extensions;
            }

            public Request ToRequest()
            {
                return new Request(certId.ToAsn1Object(), extensions);
            }
        }

        /// <summary>Add a request for the given CertificateID.</summary>
        /// <param name="certId">Certificate ID of interest.</param>
        public void AddRequest(CertificateID certId)
        {
            m_list.Add(new RequestObject(certId, null));
        }

        /// <summary>Add a request with extensions.</summary>
        /// <param name="certId">Certificate ID of interest.</param>
        /// <param name="singleRequestExtensions">The extensions to attach to the request.</param>
        public void AddRequest(CertificateID certId, X509Extensions singleRequestExtensions)
        {
            m_list.Add(new RequestObject(certId, singleRequestExtensions));
        }

        /// <summary>Set the requestor name to the passed in X509Name.</summary>
        /// <param name="requestorName">An X509Name representing the requestor name.</param>
        public void SetRequestorName(X509Name requestorName)
        {
            try
            {
                m_requestorName = new GeneralName(GeneralName.DirectoryName, requestorName);
            }
            catch (Exception e)
            {
                throw new ArgumentException("cannot encode principal", e);
            }
        }

        public void SetRequestorName(GeneralName requestorName)
        {
            m_requestorName = requestorName;
        }

        public void SetRequestExtensions(X509Extensions requestExtensions)
        {
            m_requestExtensions = requestExtensions;
        }

        private OcspReq GenerateRequest(ISignatureFactory signatureFactory, X509Certificate[] chain)
        {
            DerSequence requests;
            try
            {
                requests = DerSequence.Map(m_list, ro => ro.ToRequest());
            }
            catch (Exception e)
            {
                throw new OcspException("exception creating Request", e);
            }

            var tbsRequest = new TbsRequest(m_requestorName, requests, m_requestExtensions);

            Signature optionalSignature = null;
            if (signatureFactory != null)
            {
                if (m_requestorName == null)
                    throw new OcspException("requestorName must be specified if request is signed.");

                AlgorithmIdentifier sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

                DerBitString signature;
                try
                {
                    signature = X509.X509Utilities.GenerateSignature(signatureFactory, tbsRequest);
                }
                catch (Exception e)
                {
                    throw new OcspException("exception processing TBSRequest", e);
                }

                DerSequence certs = null;
                if (!Arrays.IsNullOrEmpty(chain))
                {
                    certs = DerSequence.Map(chain, c => c.CertificateStructure);
                }

                optionalSignature = new Signature(sigAlgID, signature, certs);
            }

            return new OcspReq(new OcspRequest(tbsRequest, optionalSignature));
        }

        /// <summary>Generate an unsigned request.</summary>
        public OcspReq Generate() => GenerateRequest(null, null);

        public OcspReq Generate(string signingAlgorithm, AsymmetricKeyParameter privateKey, X509Certificate[] chain)
        {
            return Generate(signingAlgorithm, privateKey, chain, random: null);
        }

        public OcspReq Generate(string signingAlgorithm, AsymmetricKeyParameter privateKey, X509Certificate[] chain,
            SecureRandom random)
        {
            if (signingAlgorithm == null)
                throw new ArgumentNullException(nameof(signingAlgorithm));

            return GenerateRequest(new Asn1SignatureFactory(signingAlgorithm, privateKey, random), chain);
        }

        public OcspReq Generate(ISignatureFactory signatureFactory, X509Certificate[] chain)
        {
            if (signatureFactory == null)
                throw new ArgumentNullException(nameof(signatureFactory));

            return GenerateRequest(signatureFactory, chain);
        }

        /// <summary>Return an IEnumerable of the signature names supported by the generator.</summary>
        public IEnumerable<string> SignatureAlgNames => Asn1SignatureFactory.SignatureAlgNames;
    }
}
