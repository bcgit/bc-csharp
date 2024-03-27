using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Mozilla
{
    public sealed class SignedPublicKeyAndChallenge
    {
        private readonly Asn1.Mozilla.SignedPublicKeyAndChallenge m_spkac;

        public SignedPublicKeyAndChallenge(byte[] encoding)
            : this(Asn1.Mozilla.SignedPublicKeyAndChallenge.GetInstance(encoding))
        {
        }

        public SignedPublicKeyAndChallenge(Asn1.Mozilla.SignedPublicKeyAndChallenge spkac)
        {
            m_spkac = spkac ?? throw new ArgumentNullException(nameof(spkac));
        }

        public AsymmetricKeyParameter GetPublicKey() => PublicKeyFactory.CreateKey(m_spkac.PublicKeyAndChallenge.Spki);

        public bool IsSignatureValid(AsymmetricKeyParameter publicKey) =>
            CheckSignatureValid(new Asn1VerifierFactory(m_spkac.SignatureAlgorithm, publicKey));

        public bool IsSignatureValid(IVerifierFactoryProvider verifierProvider) =>
            CheckSignatureValid(verifierProvider.CreateVerifierFactory(m_spkac.SignatureAlgorithm));

        public Asn1.Mozilla.SignedPublicKeyAndChallenge ToAsn1Structure() => m_spkac;

        public void Verify(AsymmetricKeyParameter publicKey) =>
            CheckSignature(new Asn1VerifierFactory(m_spkac.SignatureAlgorithm, publicKey));

        public void Verify(IVerifierFactoryProvider verifierProvider) =>
            CheckSignature(verifierProvider.CreateVerifierFactory(m_spkac.SignatureAlgorithm));

        private void CheckSignature(IVerifierFactory verifier)
        {
            if (!CheckSignatureValid(verifier))
                throw new InvalidKeyException("Public key presented not for SPKAC signature");
        }

        private bool CheckSignatureValid(IVerifierFactory verifier) =>
            X509.X509Utilities.VerifySignature(verifier, m_spkac.PublicKeyAndChallenge, m_spkac.Signature);
    }
}
