using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Mozilla
{
    /// <summary>A Netscape signed public key and challenge (SPKAC), as produced by the HTML keygen element.</summary>
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

        /// <summary>Determine whether the signature is valid for the given public key.</summary>
        /// <param name="publicKey">The public key to verify with.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        public bool IsSignatureValid(AsymmetricKeyParameter publicKey) =>
            CheckSignatureValid(new Asn1VerifierFactory(m_spkac.SignatureAlgorithm, publicKey));

        /// <summary>Determine whether the signature is valid using the given verifier provider.</summary>
        /// <param name="verifierProvider">The provider of the signature verifier.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        public bool IsSignatureValid(IVerifierFactoryProvider verifierProvider) =>
            CheckSignatureValid(verifierProvider.CreateVerifierFactory(m_spkac.SignatureAlgorithm));

        /// <summary>Return the underlying ASN.1 structure.</summary>
        /// <returns>The structure.</returns>
        public Asn1.Mozilla.SignedPublicKeyAndChallenge ToAsn1Structure() => m_spkac;

        /// <summary>Verify the signature with the given public key.</summary>
        /// <param name="publicKey">The public key to verify with.</param>
        /// <exception cref="InvalidKeyException">The signature is not valid.</exception>
        public void Verify(AsymmetricKeyParameter publicKey) =>
            CheckSignature(new Asn1VerifierFactory(m_spkac.SignatureAlgorithm, publicKey));

        /// <summary>Verify the signature using the given verifier provider.</summary>
        /// <param name="verifierProvider">The provider of the signature verifier.</param>
        /// <exception cref="InvalidKeyException">The signature is not valid.</exception>
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
