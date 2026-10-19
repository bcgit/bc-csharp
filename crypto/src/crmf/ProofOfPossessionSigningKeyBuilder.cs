using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Builder for the signing key proof of possession (POPOSigningKey) of a certificate request.</summary>
    public class ProofOfPossessionSigningKeyBuilder
    {
        private readonly CertRequest m_certRequest;
        private readonly SubjectPublicKeyInfo m_pubKeyInfo;

        private GeneralName m_name = null;
        private PKMacValue m_publicKeyMac = null;

        /// <summary>Create a builder that signs the whole certificate request.</summary>
        /// <param name="certRequest">The certificate request.</param>
        public ProofOfPossessionSigningKeyBuilder(CertRequest certRequest)
        {
            m_certRequest = certRequest;
            m_pubKeyInfo = null;
        }

        /// <summary>Create a builder that signs the public key together with a sender name or MAC.</summary>
        /// <param name="pubKeyInfo">The public key info.</param>
        public ProofOfPossessionSigningKeyBuilder(SubjectPublicKeyInfo pubKeyInfo)
        {
            m_certRequest = null;
            m_pubKeyInfo = pubKeyInfo;
        }

        /// <summary>Set the sender name to authenticate the request.</summary>
        /// <param name="name">The sender name.</param>
        /// <returns>This builder.</returns>
        public ProofOfPossessionSigningKeyBuilder SetSender(GeneralName name)
        {
            m_name = name;
            return this;
        }

        /// <summary>Authenticate the request with a MAC over the public key.</summary>
        /// <param name="generator">The PKMAC builder.</param>
        /// <param name="password">The password for the MAC.</param>
        /// <returns>This builder.</returns>
        public ProofOfPossessionSigningKeyBuilder SetPublicKeyMac(PKMacBuilder generator, char[] password)
        {
            m_publicKeyMac = PKMacValueGenerator.Generate(generator, password, m_pubKeyInfo);
            return this;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Authenticate the request with a MAC over the public key.</summary>
        /// <param name="generator">The PKMAC builder.</param>
        /// <param name="password">The password for the MAC.</param>
        /// <returns>This builder.</returns>
        public ProofOfPossessionSigningKeyBuilder SetPublicKeyMac(PKMacBuilder generator, ReadOnlySpan<char> password)
        {
            m_publicKeyMac = PKMacValueGenerator.Generate(generator, password, m_pubKeyInfo);
            return this;
        }
#endif

        /// <summary>Build the proof of possession by signing with the given signature factory.</summary>
        /// <param name="signer">The factory for the signature calculator.</param>
        /// <exception cref="InvalidOperationException">Both a name and a public key MAC have been set.</exception>
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
