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
        private PkiBody body;
        private readonly List<InfoTypeAndValue> generalInfos = new List<InfoTypeAndValue>();
        private readonly List<X509Certificate> extraCerts = new List<X509Certificate>();

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
            generalInfos.Add(genInfo);
            return this;
        }

        public ProtectedPkiMessageBuilder SetMessageTime(DerGeneralizedTime generalizedTime)
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
            this.body = body;
            return this;
        }

        public ProtectedPkiMessageBuilder AddCmpCertificate(X509Certificate certificate)
        {
            extraCerts.Add(certificate);
            return this;
        }

        public ProtectedPkiMessage Build(ISignatureFactory signatureFactory)
        {
            if (null == body)
                throw new InvalidOperationException("body must be set before building");

            IStreamCalculator<IBlockResult> calculator = signatureFactory.CreateCalculator();

            if (!(signatureFactory.AlgorithmDetails is AlgorithmIdentifier algorithmDetails))
                throw new ArgumentException("AlgorithmDetails is not AlgorithmIdentifier");

            FinalizeHeader(algorithmDetails);
            PkiHeader header = m_hdrBuilder.Build();
            DerBitString protection = new DerBitString(CalculateSignature(calculator, header, body));
            return FinalizeMessage(header, protection);
        }

        public ProtectedPkiMessage Build(IMacFactory macFactory)
        {
            if (null == body)
                throw new InvalidOperationException("body must be set before building");

            IStreamCalculator<IBlockResult> calculator = macFactory.CreateCalculator();

            if (!(macFactory.AlgorithmDetails is AlgorithmIdentifier algorithmDetails))
                throw new ArgumentException("AlgorithmDetails is not AlgorithmIdentifier");

            FinalizeHeader(algorithmDetails);
            PkiHeader header = m_hdrBuilder.Build();
            DerBitString protection = new DerBitString(CalculateSignature(calculator, header, body));
            return FinalizeMessage(header, protection);
        }

        private void FinalizeHeader(AlgorithmIdentifier algorithmIdentifier)
        {
            m_hdrBuilder.SetProtectionAlg(algorithmIdentifier);
            if (generalInfos.Count > 0)
            {
                m_hdrBuilder.SetGeneralInfo(generalInfos.ToArray());
            }
        }

        private ProtectedPkiMessage FinalizeMessage(PkiHeader header, DerBitString protection)
        {
            if (extraCerts.Count < 1)
                return new ProtectedPkiMessage(new PkiMessage(header, body, protection));

            CmpCertificate[] cmpCertificates = new CmpCertificate[extraCerts.Count];
            for (int i = 0; i < cmpCertificates.Length; i++)
            {
                cmpCertificates[i] = new CmpCertificate(extraCerts[i].CertificateStructure);
            }

            return new ProtectedPkiMessage(new PkiMessage(header, body, protection, cmpCertificates));
        }

        private byte[] CalculateSignature(IStreamCalculator<IBlockResult> signer, PkiHeader header, PkiBody body)
        {
            new DerSequence(header, body).EncodeTo(signer.Stream);
            return signer.GetResult().Collect();
        }
    }
}
