using System;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems
{
    public sealed class MLKemEncapsulator
        : IKemEncapsulator
    {
        private readonly MLKemParameters m_parameters;

        private MLKemPublicKeyParameters m_publicKey;
        private MLKemEngine m_engine;

        public MLKemEncapsulator(MLKemParameters parameters)
        {
            m_parameters = parameters;
        }

        public void Init(ICipherParameters parameters)
        {
            parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

            if (!(parameters is MLKemPublicKeyParameters publicKey))
                throw new ArgumentException($"{nameof(MLKemEncapsulator)} expects {nameof(MLKemPublicKeyParameters)}");

            m_publicKey = publicKey;
            m_engine = GetEngine(m_publicKey.Parameters, CryptoServicesRegistrar.GetSecureRandom(providedRandom));
        }

        public int EncapsulationLength => m_engine.CryptoCipherTextBytes;

        public int SecretLength => m_engine.CryptoBytes;

        public void Encapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen)
        {
            Arrays.ValidateSegment(encBuf, encOff, encLen);
            Arrays.ValidateSegment(secBuf, secOff, secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Encapsulate(encBuf.AsSpan(encOff, encLen), secBuf.AsSpan(secOff, secLen));
#else
            if (EncapsulationLength != encLen)
                throw new ArgumentException(nameof(encLen));
            if (SecretLength != secLen)
                throw new ArgumentException(nameof(secLen));

            byte[] r = new byte[32];
            m_engine.Random.NextBytes(r);
            m_engine.KemEncrypt(encBuf, encOff, secBuf, secOff, m_publicKey.GetEncoded(), r);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Encapsulate(Span<byte> encapsulation, Span<byte> secret)
        {
            if (EncapsulationLength != encapsulation.Length)
                throw new ArgumentException(nameof(encapsulation));
            if (SecretLength != secret.Length)
                throw new ArgumentException(nameof(secret));

            Span<byte> r = stackalloc byte[32];
            m_engine.Random.NextBytes(r);
            m_engine.KemEncrypt(encapsulation, secret, m_publicKey.GetEncoded(), r);
        }
#endif

        private MLKemEngine GetEngine(MLKemParameters keyParameters, SecureRandom random)
        {
            var keyParameterSet = keyParameters.ParameterSet;

            if (keyParameterSet != m_parameters.ParameterSet)
                throw new ArgumentException("Mismatching key parameter set", nameof(keyParameters));

            return keyParameterSet.GetEngine(random);
        }
    }
}
