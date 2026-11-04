using System;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems
{
    /// <summary>Encapsulator for the ML-KEM key encapsulation mechanism.</summary>
    public sealed class MLKemEncapsulator
        : IKemEncapsulator
    {
        private readonly MLKemParameters m_parameters;

        private MLKemPublicKeyParameters m_publicKey;
        private SecureRandom m_random;
        private MLKemEngine m_engine;

        /// <summary>Create a new <see cref="MLKemEncapsulator"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        public MLKemEncapsulator(MLKemParameters parameters)
        {
            m_parameters = parameters;
        }

        /// <inheritdoc/>
        public void Init(ICipherParameters parameters)
        {
            parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

            if (!(parameters is MLKemPublicKeyParameters publicKey))
                throw new ArgumentException($"{nameof(MLKemEncapsulator)} expects {nameof(MLKemPublicKeyParameters)}");

            m_publicKey = publicKey;
            m_random = CryptoServicesRegistrar.GetSecureRandom(providedRandom);
            m_engine = GetEngine(m_publicKey.Parameters);
        }

        /// <inheritdoc/>
        public int EncapsulationLength => m_engine.CipherTextBytes;

        /// <inheritdoc/>
        public int SecretLength => MLKemEngine.SharedSecretBytes;

        /// <inheritdoc/>
        public void Encapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen)
        {
            Arrays.ValidateSegment(encBuf, encOff, encLen);
            Arrays.ValidateSegment(secBuf, secOff, secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Encapsulate(encBuf.AsSpan(encOff, encLen), secBuf.AsSpan(secOff, secLen));
#else
            if (EncapsulationLength != encLen)
                throw new ArgumentException($"Expected {EncapsulationLength}", nameof(encLen));
            if (SecretLength != secLen)
                throw new ArgumentException($"Expected {SecretLength}", nameof(secLen));

            byte[] randBytes = new byte[MLKemEngine.SymBytes];
            m_random.NextBytes(randBytes);

            m_engine.KemEncrypt(m_publicKey.Encoding, randBytes, encBuf, encOff, secBuf, secOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void Encapsulate(Span<byte> encapsulation, Span<byte> secret)
        {
            if (EncapsulationLength != encapsulation.Length)
                throw new ArgumentException($"Expected length {EncapsulationLength}", nameof(encapsulation));
            if (SecretLength != secret.Length)
                throw new ArgumentException($"Expected length {SecretLength}", nameof(secret));

            Span<byte> randBytes = stackalloc byte[MLKemEngine.SymBytes];
            m_random.NextBytes(randBytes);

            m_engine.KemEncrypt(m_publicKey.Encoding.AsSpan(), randBytes, encapsulation, secret);
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
