using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    // TODO[api] Make sealed
    public class HqcKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly HqcPrivateKeyParameters m_privateKey;
        private readonly HqcEngine m_engine;

        // TODO[api] 'privateKey'
        public HqcKemExtractor(HqcPrivateKeyParameters privParams)
        {
            m_privateKey = privParams ?? throw new ArgumentNullException(nameof(privParams));
            m_engine = privParams.Parameters.Engine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            if (encapsulation == null)
                throw new ArgumentNullException(nameof(encapsulation));
            // Decaps reads u, v and the salt at fixed offsets and only compares u and v, so without this check
            // trailing bytes would be ignored and a lengthened ciphertext would decapsulate to the same secret
            if (encapsulation.Length != m_engine.CipherTextBytes)
                throw new ArgumentException($"Expected length {m_engine.CipherTextBytes}", nameof(encapsulation));

            byte[] ss = new byte[64];

            m_engine.Decaps(ss, ct: encapsulation, m_privateKey.GetExpandedKey());

            byte[] secret = Arrays.CopySegment(ss, 0, 32);
            Arrays.ZeroMemory(ss);
            return secret;
        }

        public int EncapsulationLength => m_engine.CipherTextBytes;
    }
}
