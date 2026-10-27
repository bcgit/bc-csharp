using System;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems
{
    /// <summary>Decapsulator for the ML-KEM key encapsulation mechanism.</summary>
    public sealed class MLKemDecapsulator
        : IKemDecapsulator
    {
        private readonly MLKemParameters m_parameters;

        private MLKemPrivateKeyParameters m_privateKey;
        private MLKemEngine m_engine;

        /// <summary>Create a new <see cref="MLKemDecapsulator"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        public MLKemDecapsulator(MLKemParameters parameters)
        {
            m_parameters = parameters;
        }

        /// <inheritdoc/>
        public void Init(ICipherParameters parameters)
        {
            parameters = ParameterUtilities.IgnoreRandom(parameters);

            if (!(parameters is MLKemPrivateKeyParameters privateKey))
                throw new ArgumentException($"{nameof(MLKemDecapsulator)} expects {nameof(MLKemPrivateKeyParameters)}");

            m_privateKey = privateKey;
            m_engine = GetEngine(m_privateKey.Parameters);
        }

        /// <inheritdoc/>
        public int EncapsulationLength => m_engine.CipherTextBytes;

        /// <inheritdoc/>
        public int SecretLength => MLKemEngine.SharedSecretBytes;

        /// <inheritdoc/>
        public void Decapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen)
        {
            Arrays.ValidateSegment(encBuf, encOff, encLen);
            Arrays.ValidateSegment(secBuf, secOff, secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Decapsulate(encBuf.AsSpan(encOff, encLen), secBuf.AsSpan(secOff, secLen));
#else
            if (EncapsulationLength != encLen)
                throw new ArgumentException($"Expected {EncapsulationLength}", nameof(encLen));
            if (SecretLength != secLen)
                throw new ArgumentException($"Expected {SecretLength}", nameof(secLen));

            m_engine.KemDecrypt(m_privateKey.Encoding, encBuf, encOff, secBuf, secOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void Decapsulate(ReadOnlySpan<byte> encapsulation, Span<byte> secret)
        {
            if (EncapsulationLength != encapsulation.Length)
                throw new ArgumentException($"Expected length {EncapsulationLength}", nameof(encapsulation));
            if (SecretLength != secret.Length)
                throw new ArgumentException($"Expected length {SecretLength}", nameof(secret));

            m_engine.KemDecrypt(m_privateKey.Encoding.AsSpan(), encapsulation, secret);
        }
#endif

        private MLKemEngine GetEngine(MLKemParameters keyParameters)
        {
            var keyParameterSet = keyParameters.ParameterSet;

            if (keyParameterSet != m_parameters.ParameterSet)
                throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

            return keyParameterSet.Engine;
        }
    }
}
