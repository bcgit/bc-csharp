using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crmf
{
    public class ProofOfPossessionSigningKeyBuilder
    {
        private readonly CertRequest m_certRequest;
        private readonly SubjectPublicKeyInfo m_pubKeyInfo;

        private GeneralName m_name = null;
        private PKMacValue m_publicKeyMac = null;

        public ProofOfPossessionSigningKeyBuilder(CertRequest certRequest)
        {
            m_certRequest = certRequest;
            m_pubKeyInfo = null;
        }

        public ProofOfPossessionSigningKeyBuilder(SubjectPublicKeyInfo pubKeyInfo)
        {
            m_certRequest = null;
            m_pubKeyInfo = pubKeyInfo;
        }

        public ProofOfPossessionSigningKeyBuilder SetSender(GeneralName name)
        {
            m_name = name;
            return this;
        }

        public ProofOfPossessionSigningKeyBuilder SetPublicKeyMac(PKMacBuilder generator, char[] password)
        {
            m_publicKeyMac = PKMacValueGenerator.Generate(generator, password, m_pubKeyInfo);
            return this;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ProofOfPossessionSigningKeyBuilder SetPublicKeyMac(PKMacBuilder generator, ReadOnlySpan<char> password)
        {
            m_publicKeyMac = PKMacValueGenerator.Generate(generator, password, m_pubKeyInfo);
            return this;
        }
#endif

        public PopoSigningKey Build(ISignatureFactory signer)
        {
            if (m_name != null && m_publicKeyMac != null)
                throw new InvalidOperationException("name and publicKeyMAC cannot both be set.");

            PopoSigningKeyInput popo;
            Asn1Encodable asn1Encodable;

            if (m_certRequest != null)
            {
                popo = null;
                asn1Encodable = m_certRequest;
            }
            else if (m_name != null)
            {
                popo = new PopoSigningKeyInput(m_name, m_pubKeyInfo);
                asn1Encodable = popo;
            }
            else
            {
                popo = new PopoSigningKeyInput(m_publicKeyMac, m_pubKeyInfo);
                asn1Encodable = popo;
            }

            var signature = X509.X509Utilities.GenerateSignature(signer, asn1Encodable);

            return new PopoSigningKey(popo, (AlgorithmIdentifier)signer.AlgorithmDetails, signature);
        }
    }
}
