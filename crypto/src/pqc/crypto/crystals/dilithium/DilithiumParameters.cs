using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
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
        private int k;
        private bool usingAes;

        private DilithiumParameters(string name, int param, bool usingAes)
        {
            this.name = name;
            k = param;
            this.usingAes = usingAes;
        }

        internal DilithiumEngine GetEngine(SecureRandom Random)
        {
            return new DilithiumEngine(k, Random, usingAes);
        }

        public string Name => name;
    }
}