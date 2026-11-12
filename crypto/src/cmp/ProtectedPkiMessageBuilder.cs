using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>Builder for protected PKIMessages (RFC 4210).</summary>
    /// <remarks>
    /// Set the header fields and the body, add any extra certificates, then call one of the <c>Build</c> methods to
    /// protect the message with a signature or a MAC.
    /// </remarks>
    public sealed class ProtectedPkiMessageBuilder
    {
        private readonly PkiHeaderBuilder m_hdrBuilder;
        private readonly List<InfoTypeAndValue> m_generalInfos = new List<InfoTypeAndValue>();
        private readonly List<X509Certificate> m_extraCerts = new List<X509Certificate>();
        private PkiBody m_body;

        /// <summary>Create a builder for a CMP 2000 message.</summary>
        /// <param name="sender">The sender of the message.</param>
        /// <param name="recipient">The recipient of the message.</param>
        public ProtectedPkiMessageBuilder(GeneralName sender, GeneralName recipient)
            : this(PkiHeader.CMP_2000, sender, recipient)
        {
        }

        /// <summary>Create a builder for a message with the given protocol version.</summary>
        /// <param name="pvno">The protocol version number.</param>
        /// <param name="sender">The sender of the message.</param>
        /// <param name="recipient">The recipient of the message.</param>
        public ProtectedPkiMessageBuilder(int pvno, GeneralName sender, GeneralName recipient)
        {
            m_hdrBuilder = new PkiHeaderBuilder(pvno, sender, recipient);
        }

        /// <summary>Set the transaction ID of the message header.</summary>
        /// <param name="tid">The transaction ID.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetTransactionId(byte[] tid)
        {
            m_hdrBuilder.SetTransactionID(tid);
            return this;
        }

        /// <summary>Set the free text of the message header.</summary>
        /// <param name="freeText">The free text.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetFreeText(PkiFreeText freeText)
        {
            m_hdrBuilder.SetFreeText(freeText);
            return this;
        }

        /// <summary>Add an item of general information to the message header.</summary>
        /// <param name="genInfo">The information to add.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder AddGeneralInfo(InfoTypeAndValue genInfo)
        {
            m_generalInfos.Add(genInfo);
            return this;
        }

        /// <summary>Set the message time of the message header.</summary>
        /// <param name="time">The time.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetMessageTime(DateTime time)
        {
            m_hdrBuilder.SetMessageTime(new Asn1GeneralizedTime(time));
            return this;
        }

        /// <summary>Set the message time of the message header.</summary>
        /// <param name="generalizedTime">The time.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetMessageTime(Asn1GeneralizedTime generalizedTime)
        {
            m_hdrBuilder.SetMessageTime(generalizedTime);
            return this;
        }

        /// <summary>Set the recipient key identifier of the message header.</summary>
        /// <param name="id">The identifier.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetRecipKID(byte[] id)
        {
            m_hdrBuilder.SetRecipKID(id);
            return this;
        }

        /// <summary>Set the recipient nonce of the message header.</summary>
        /// <param name="nonce">The nonce.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetRecipNonce(byte[] nonce)
        {
            m_hdrBuilder.SetRecipNonce(nonce);
            return this;
        }

        /// <summary>Set the sender key identifier of the message header.</summary>
        /// <param name="id">The identifier.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetSenderKID(byte[] id)
        {
            m_hdrBuilder.SetSenderKID(id);
            return this;
        }

        /// <summary>Set the sender nonce of the message header.</summary>
        /// <param name="nonce">The nonce.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetSenderNonce(byte[] nonce)
        {
            m_hdrBuilder.SetSenderNonce(nonce);
            return this;
        }

        /// <summary>Set the body of the message.</summary>
        /// <param name="body">The body.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder SetBody(PkiBody body)
        {
            m_body = body;
            return this;
        }

        /// <summary>Set the body of the message to certificate request messages.</summary>
        /// <param name="bodyType">The PKIBody type; it must be a certificate request type.</param>
        /// <param name="certificateReqMessages">The request messages.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentException">The body type does not match the content.</exception>
        public ProtectedPkiMessageBuilder SetBody(int bodyType, CertificateReqMessages certificateReqMessages)
        {
            if (!CertificateReqMessages.IsCertificateRequestMessages(bodyType))
                throw new ArgumentException("body type " + bodyType + " does not match CMP type CertReqMessages");

            m_body = new PkiBody(bodyType, certificateReqMessages.ToAsn1Structure());
            return this;
        }

        /// <summary>Set the body of the message to a certificate response message.</summary>
        /// <param name="bodyType">The PKIBody type; it must be a certificate response type.</param>
        /// <param name="certificateRepMessage">The response message.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentException">The body type does not match the content.</exception>
        public ProtectedPkiMessageBuilder SetBody(int bodyType, CertificateRepMessage certificateRepMessage)
        {
            if (!CertificateRepMessage.IsCertificateRepMessage(bodyType))
                throw new ArgumentException("body type " + bodyType + " does not match CMP type CertRepMessage");

            m_body = new PkiBody(bodyType, certificateRepMessage.ToAsn1Structure());
            return this;
        }

        /// <summary>Set the body of the message to certificate confirmation content.</summary>
        /// <param name="bodyType">The PKIBody type; it must be the certificate confirmation type.</param>
        /// <param name="certificateConfirmationContent">The confirmation content.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="ArgumentException">The body type does not match the content.</exception>
        public ProtectedPkiMessageBuilder SetBody(int bodyType,
            CertificateConfirmationContent certificateConfirmationContent)
        {
            if (!CertificateConfirmationContent.IsCertificateConfirmationContent(bodyType))
                throw new ArgumentException("body type " + bodyType + " does not match CMP type CertConfirmContent");

            m_body = new PkiBody(bodyType, certificateConfirmationContent.ToAsn1Structure());
            return this;
        }

        /// <summary>Add an extra certificate to the message.</summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>This builder.</returns>
        public ProtectedPkiMessageBuilder AddCmpCertificate(X509Certificate certificate)
        {
            m_extraCerts.Add(certificate);
            return this;
        }

        /// <summary>Build the message, protecting it with a signature.</summary>
        /// <param name="signatureFactory">The factory for the signature calculator.</param>
        /// <returns>The protected message.</returns>
        /// <exception cref="InvalidOperationException">The body has not been set.</exception>
        /// <exception cref="ArgumentException">The algorithm details are not an AlgorithmIdentifier.</exception>
        public ProtectedPkiMessage Build(ISignatureFactory signatureFactory)
        {
            if (null == m_body)
                throw new InvalidOperationException("body must be set before building");

            if (!(signatureFactory.AlgorithmDetails is AlgorithmIdentifier algorithmDetails))
                throw new ArgumentException("AlgorithmDetails is not AlgorithmIdentifier");

            FinalizeHeader(algorithmDetails);
            PkiHeader header = m_hdrBuilder.Build();
            DerBitString protection = X509Utilities.GenerateSignature(signatureFactory,
                new DerSequence(header, m_body));
            return FinalizeMessage(header, protection);
        }

        /// <summary>Build the message, protecting it with a MAC.</summary>
        /// <param name="macFactory">The factory for the MAC calculator.</param>
        /// <returns>The protected message.</returns>
        /// <exception cref="InvalidOperationException">The body has not been set.</exception>
        /// <exception cref="ArgumentException">The algorithm details are not an AlgorithmIdentifier.</exception>
        public ProtectedPkiMessage Build(IMacFactory macFactory)
        {
            if (null == m_body)
                throw new InvalidOperationException("body must be set before building");

            if (!(macFactory.AlgorithmDetails is AlgorithmIdentifier algorithmDetails))
                throw new ArgumentException("AlgorithmDetails is not AlgorithmIdentifier");

            FinalizeHeader(algorithmDetails);
            PkiHeader header = m_hdrBuilder.Build();
            DerBitString protection = X509Utilities.GenerateMac(macFactory, new DerSequence(header, m_body));
            return FinalizeMessage(header, protection);
        }

        private void FinalizeHeader(AlgorithmIdentifier algorithmIdentifier)
        {
            m_hdrBuilder.SetProtectionAlg(algorithmIdentifier);
            if (m_generalInfos.Count > 0)
            {
                m_hdrBuilder.SetGeneralInfo(m_generalInfos.ToArray());
            }
        }

        private ProtectedPkiMessage FinalizeMessage(PkiHeader header, DerBitString protection)
        {
            if (m_extraCerts.Count < 1)
                return new ProtectedPkiMessage(new PkiMessage(header, m_body, protection));

            CmpCertificate[] cmpCertificates = new CmpCertificate[m_extraCerts.Count];
            for (int i = 0; i < cmpCertificates.Length; i++)
            {
                cmpCertificates[i] = new CmpCertificate(m_extraCerts[i].CertificateStructure);
            }

            return new ProtectedPkiMessage(new PkiMessage(header, m_body, protection, cmpCertificates));
        }
    }
}
