using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    [Obsolete("Use ML-DSA instead")]
    public sealed class DilithiumParameters
        : ICipherParameters
    {
        public static DilithiumParameters Dilithium2 = new DilithiumParameters("dilithium2", 2, false);
        [Obsolete("Parameter set to be removed")]
        public static DilithiumParameters Dilithium2Aes = new DilithiumParameters("dilithium2aes", 2, true);
        
        public static DilithiumParameters Dilithium3 = new DilithiumParameters("dilithium3", 3, false);
        [Obsolete("Parameter set to be removed")]
        public static DilithiumParameters Dilithium3Aes = new DilithiumParameters("dilithium3aes", 3, true);
        
        public static DilithiumParameters Dilithium5 = new DilithiumParameters("dilithium5", 5, false);
        [Obsolete("Parameter set to be removed")]
        public static DilithiumParameters Dilithium5Aes = new DilithiumParameters("dilithium5aes", 5, true);

        private string name;
        private readonly int m_mode;
        private readonly bool m_usingAes;

        private DilithiumParameters(string name, int mode, bool usingAes)
        {
            this.name = name;
            m_mode = mode;
            m_usingAes = usingAes;
        }

        internal DilithiumEngine GetEngine(SecureRandom Random) => new DilithiumEngine(m_mode, Random, m_usingAes);

        public string Name => name;
    }
}
