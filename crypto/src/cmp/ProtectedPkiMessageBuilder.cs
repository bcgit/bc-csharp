using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public sealed class ProtectedPkiMessageBuilder
    {
        private readonly PkiHeaderBuilder m_hdrBuilder;
        private readonly List<InfoTypeAndValue> m_generalInfos = new List<InfoTypeAndValue>();
        private readonly List<X509Certificate> m_extraCerts = new List<X509Certificate>();
        private PkiBody m_body;

        public ProtectedPkiMessageBuilder(GeneralName sender, GeneralName recipient)
            : this(PkiHeader.CMP_2000, sender, recipient)
        {
        }

        public ProtectedPkiMessageBuilder(int pvno, GeneralName sender, GeneralName recipient)
        {
            m_hdrBuilder = new PkiHeaderBuilder(pvno, sender, recipient);
        }

        public ProtectedPkiMessageBuilder SetTransactionId(byte[] tid)
        {
            m_hdrBuilder.SetTransactionID(tid);
            return this;
        }

        public ProtectedPkiMessageBuilder SetFreeText(PkiFreeText freeText)
        {
            m_hdrBuilder.SetFreeText(freeText);
            return this;
        }

        public ProtectedPkiMessageBuilder AddGeneralInfo(InfoTypeAndValue genInfo)
        {
            m_generalInfos.Add(genInfo);
            return this;
        }

        public ProtectedPkiMessageBuilder SetMessageTime(DateTime time)
        {
            m_hdrBuilder.SetMessageTime(new Asn1GeneralizedTime(time));
            return this;
        }

        public ProtectedPkiMessageBuilder SetMessageTime(Asn1GeneralizedTime generalizedTime)
        {
            m_hdrBuilder.SetMessageTime(generalizedTime);
            return this;
        }

        public ProtectedPkiMessageBuilder SetRecipKID(byte[] id)
        {
            m_hdrBuilder.SetRecipKID(id);
            return this;
        }

        public ProtectedPkiMessageBuilder SetRecipNonce(byte[] nonce)
        {
            m_hdrBuilder.SetRecipNonce(nonce);
            return this;
        }

        public ProtectedPkiMessageBuilder SetSenderKID(byte[] id)
        {
            m_hdrBuilder.SetSenderKID(id);
            return this;
        }

        public ProtectedPkiMessageBuilder SetSenderNonce(byte[] nonce)
        {
            m_hdrBuilder.SetSenderNonce(nonce);
            return this;
        }

        public ProtectedPkiMessageBuilder SetBody(PkiBody body)
        {
            m_body = body;
            return this;
        }

        // TODO[crmf] Add CertificateReqMessages
        //public ProtectedPkiMessageBuilder SetBody(int bodyType, CertificateReqMessages certificateReqMessages)
        //{
        //    if (!CertificateReqMessages.IsCertificateRequestMessages(bodyType))
        //        throw new ArgumentException("body type " + bodyType + " does not match CMP type CertReqMessages");

        //    m_body = new PkiBody(bodyType, certificateReqMessages.ToAsn1Structure());
        //    return this;
        //}

        // TODO[crmf] Add CertificateRepMessage
        //public ProtectedPkiMessageBuilder SetBody(int bodyType, CertificateRepMessage certificateRepMessage)
        //{
        //    if (!CertificateRepMessage.IsCertificateRepMessage(bodyType))
        //        throw new ArgumentException("body type " + bodyType + " does not match CMP type CertRepMessage");

        //    m_body = new PkiBody(bodyType, certificateRepMessage.ToAsn1Structure());
        //    return this;
        //}

        public ProtectedPkiMessageBuilder SetBody(int bodyType,
            CertificateConfirmationContent certificateConfirmationContent)
        {
            if (!CertificateConfirmationContent.IsCertificateConfirmationContent(bodyType))
                throw new ArgumentException("body type " + bodyType + " does not match CMP type CertConfirmContent");

            m_body = new PkiBody(bodyType, certificateConfirmationContent.ToAsn1Structure());
            return this;
        }

        public ProtectedPkiMessageBuilder AddCmpCertificate(X509Certificate certificate)
        {
            m_extraCerts.Add(certificate);
            return this;
        }

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
