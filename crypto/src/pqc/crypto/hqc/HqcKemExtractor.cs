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
            byte[] ss = new byte[64];
            byte[] sk = m_privateKey.InternalPrivateKey;

            m_engine.Decaps(ss, ct: encapsulation, sk);

            return Arrays.CopySegment(ss, 0, 32);
        }

        public int EncapsulationLength => m_engine.CipherTextBytes;
    }
}
