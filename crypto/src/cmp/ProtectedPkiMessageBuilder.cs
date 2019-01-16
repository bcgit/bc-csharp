using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public class ProtectedPkiMessageBuilder
    {
        private PkiHeaderBuilder hdrBuilBuilder;
        private PkiBody body;
        private List<object> generalInfos = new List<object>();
        private List<object> extraCerts = new List<object>();

        public ProtectedPkiMessageBuilder(GeneralName sender, GeneralName recipient) : this(PkiHeader.CMP_2000, sender,
            recipient)
        {
        }


        public ProtectedPkiMessageBuilder(int pvno, GeneralName sender, GeneralName recipient)
        {
            hdrBuilBuilder = new PkiHeaderBuilder(pvno, sender, recipient);
        }

        public ProtectedPkiMessageBuilder SetTransactionId(byte[] tid)
        {
            hdrBuilBuilder.SetTransactionID(tid);
            return this;
        }

        public ProtectedPkiMessageBuilder SetFreeText(PkiFreeText freeText)
        {
            hdrBuilBuilder.SetFreeText(freeText);
            return this;
        }

        public ProtectedPkiMessageBuilder AddGeneralInfo(InfoTypeAndValue genInfo)
        {
            generalInfos.Add(genInfo);
            return this;
        }

        public ProtectedPkiMessageBuilder SetMessageTime(DerGeneralizedTime generalizedTime)
        {
            hdrBuilBuilder.SetMessageTime(generalizedTime);
            return this;
        }

        public ProtectedPkiMessageBuilder SetRecipKID(byte[] id)
        {
            hdrBuilBuilder.SetRecipKID(id);
            return this;
        }

        public ProtectedPkiMessageBuilder SetRecipNonce(byte[] nonce)
        {
            hdrBuilBuilder.SetRecipNonce(nonce);
            return this;
        }

        public ProtectedPkiMessageBuilder SetSenderKID(byte[] id)
        {
            hdrBuilBuilder.SetSenderKID(id);
            return this;
        }

        public ProtectedPkiMessageBuilder SetSenderNonce(byte[] nonce)
        {
            hdrBuilBuilder.SetSenderNonce(nonce);
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
            IStreamCalculator calculator = signatureFactory.CreateCalculator();

            if (!(signatureFactory.AlgorithmDetails is AlgorithmIdentifier))
            {
                throw new ArgumentException("AlgorithmDetails is not AlgorithmIdentifier");
            }

            FinalizeHeader((AlgorithmIdentifier) signatureFactory.AlgorithmDetails);
            PkiHeader header = hdrBuilBuilder.Build();
            DerBitString protection = new DerBitString(CalculateSignature(calculator, header, body));
            return FinalizeMessage(header, protection);
        }

        public ProtectedPkiMessage Build(IMacFactory factory)
        {           
                IStreamCalculator calculator = factory.CreateCalculator();                
                FinalizeHeader((AlgorithmIdentifier)factory.AlgorithmDetails);
                PkiHeader header = hdrBuilBuilder.Build();
                DerBitString protection = new DerBitString(CalculateSignature(calculator, header, body));
                return FinalizeMessage(header, protection);        
        }


        private void FinalizeHeader(AlgorithmIdentifier algorithmIdentifier)
        {
            hdrBuilBuilder.SetProtectionAlg(algorithmIdentifier);
            if (generalInfos.Count > 0)
            {
                InfoTypeAndValue[] genInfos = new InfoTypeAndValue[generalInfos.Count];
                for (int t = 0; t < genInfos.Length; t++)
                {
                    genInfos[t] = (InfoTypeAndValue) generalInfos[t];
                }

                hdrBuilBuilder.SetGeneralInfo(genInfos);
            }
        }

        private ProtectedPkiMessage FinalizeMessage(PkiHeader header, DerBitString protection)
        {
            if (extraCerts.Count > 0)
            {
                CmpCertificate[] cmpCertificates = new CmpCertificate[extraCerts.Count];
                for (int i = 0; i < cmpCertificates.Length; i++)
                {
                    byte[] cert = ((X509Certificate) extraCerts[i]).GetEncoded();
                    cmpCertificates[i] = CmpCertificate.GetInstance((Asn1Sequence.FromByteArray(cert)));
                }

                return new ProtectedPkiMessage(new PkiMessage(header, body, protection, cmpCertificates));
            }

            return new ProtectedPkiMessage(new PkiMessage(header, body, protection));
        }

        private byte[] CalculateSignature(IStreamCalculator signer, PkiHeader header, PkiBody body)
        {
            Asn1EncodableVector avec = new Asn1EncodableVector();
            avec.Add(header);
            avec.Add(body);
            byte[] encoded = new DerSequence(avec).GetEncoded();
            signer.Stream.Write(encoded, 0, encoded.Length);
            Object result = signer.GetResult();

            if (result is DefaultSignatureResult)
            {
                return ((DefaultSignatureResult)result).Collect();
            }
            else if (result is IBlockResult)
            {
                return ((IBlockResult)result).Collect();
            }
            else if (result is byte[])
            {
                return (byte[]) result;
            }

            throw new InvalidOperationException("result is not byte[] or DefaultSignatureResult");
        }
    }
}