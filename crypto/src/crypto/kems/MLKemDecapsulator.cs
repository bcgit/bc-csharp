using System;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems
{
    public sealed class MLKemDecapsulator
        : IKemDecapsulator
    {
        private readonly MLKemParameters m_parameters;

        private MLKemPrivateKeyParameters m_privateKey;
        private MLKemEngine m_engine;

        public MLKemDecapsulator(MLKemParameters parameters)
        {
            m_parameters = parameters;
        }

        public void Init(ICipherParameters parameters)
        {
            parameters = ParameterUtilities.IgnoreRandom(parameters);

            if (!(parameters is MLKemPrivateKeyParameters privateKey))
                throw new ArgumentException($"{nameof(MLKemDecapsulator)} expects {nameof(MLKemPrivateKeyParameters)}");

            m_privateKey = privateKey;
            m_engine = GetEngine(m_privateKey.Parameters);
        }

        public int EncapsulationLength => m_engine.CipherTextBytes;

        public int SecretLength => MLKemEngine.SharedSecretBytes;

        public void Decapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen)
        {
            Arrays.ValidateSegment(encBuf, encOff, encLen);
            Arrays.ValidateSegment(secBuf, secOff, secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Decapsulate(encBuf.AsSpan(encOff, encLen), secBuf.AsSpan(secOff, secLen));
#else
            if (EncapsulationLength != encLen)
                throw new ArgumentException(nameof(encLen));
            if (SecretLength != secLen)
                throw new ArgumentException(nameof(secLen));

            m_engine.KemDecrypt(m_privateKey.Encoding, encBuf, encOff, secBuf, secOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Decapsulate(ReadOnlySpan<byte> encapsulation, Span<byte> secret)
        {
            if (EncapsulationLength != encapsulation.Length)
                throw new ArgumentException(nameof(encapsulation));
            if (SecretLength != secret.Length)
                throw new ArgumentException(nameof(secret));

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
