using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    public class DilithiumParameters
        : ICipherParameters
    {
        public static DilithiumParameters Dilithium2 = new DilithiumParameters(2, false);
        public static DilithiumParameters Dilithium2Aes = new DilithiumParameters(2, true);
        
        public static DilithiumParameters Dilithium3 = new DilithiumParameters(3, false);
        public static DilithiumParameters Dilithium3Aes = new DilithiumParameters(3, true);
        
        public static DilithiumParameters Dilithium5 = new DilithiumParameters(5, false);
        public static DilithiumParameters Dilithium5Aes = new DilithiumParameters(5, true);

        private int k;
        private bool usingAes;

        private DilithiumParameters(int param, bool usingAes)
        {
            k = param;
            this.usingAes = usingAes;
        }

        internal DilithiumEngine GetEngine(SecureRandom Random)
        {
            return new DilithiumEngine(k, Random, usingAes);
        }
    }
}