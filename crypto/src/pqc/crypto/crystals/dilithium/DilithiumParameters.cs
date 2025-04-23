using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    [Obsolete("Use ML-DSA instead")]
    public sealed class DilithiumParameters
        : ICipherParameters
    {
        public static DilithiumParameters Dilithium2 = new DilithiumParameters(2, false);
        [Obsolete("Parameter set to be removed")]
        public static DilithiumParameters Dilithium2Aes = new DilithiumParameters(2, true);
        
        public static DilithiumParameters Dilithium3 = new DilithiumParameters(3, false);
        [Obsolete("Parameter set to be removed")]
        public static DilithiumParameters Dilithium3Aes = new DilithiumParameters(3, true);
        
        public static DilithiumParameters Dilithium5 = new DilithiumParameters(5, false);
        [Obsolete("Parameter set to be removed")]
        public static DilithiumParameters Dilithium5Aes = new DilithiumParameters(5, true);

        private readonly int m_mode;
        private readonly bool m_usingAes;

        private DilithiumParameters(int mode, bool usingAes)
        {
            m_mode = mode;
            m_usingAes = usingAes;
        }

        internal DilithiumEngine GetEngine(SecureRandom Random) => new DilithiumEngine(m_mode, Random, m_usingAes);
    }
}
