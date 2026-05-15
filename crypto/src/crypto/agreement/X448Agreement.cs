using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>
    /// X448 (RFC 7748) Diffie-Hellman raw agreement. Init takes the local
    /// <see cref="X448PrivateKeyParameters"/>; <see cref="CalculateAgreement(ICipherParameters, byte[], int)"/>
    /// writes the 56-byte shared secret derived against the peer's
    /// <see cref="X448PublicKeyParameters"/>.
    /// </summary>
    public sealed class X448Agreement
        : IRawAgreement
    {
        private X448PrivateKeyParameters m_privateKey;

        /// <summary>Capture the local private key used for subsequent agreements.</summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="X448PrivateKeyParameters"/>.</exception>
        public void Init(ICipherParameters parameters)
        {
            m_privateKey = (X448PrivateKeyParameters)parameters;
        }

        /// <summary>Length in bytes of the shared secret produced by the agreement (56).</summary>
        public int AgreementSize
        {
            get { return X448PrivateKeyParameters.SecretSize; }
        }

        /// <summary>
        /// Perform the agreement against <paramref name="publicKey"/> and write the shared secret into
        /// <paramref name="buf"/> starting at <paramref name="off"/>.
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="publicKey"/> is not an
        /// <see cref="X448PublicKeyParameters"/>.</exception>
        /// <exception cref="InvalidOperationException">If the agreement produces an all-zero secret
        /// (degenerate peer key).</exception>
        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CalculateAgreement(publicKey, buf.AsSpan(off));
#else
            m_privateKey.GenerateSecret((X448PublicKeyParameters)publicKey, buf, off);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Span-based overload of <see cref="CalculateAgreement(ICipherParameters, byte[], int)"/>.</summary>
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> buf)
        {
            m_privateKey.GenerateSecret((X448PublicKeyParameters)publicKey, buf);
        }
#endif
    }
}
