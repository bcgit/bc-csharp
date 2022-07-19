using Org.BouncyCastle.Crypto.Engines;

namespace Org.BouncyCastle.Crypto
{
    public static class AesUtilities
    {
        public static IBlockCipher CreateEngine()
        {
#if NETCOREAPP3_0_OR_GREATER
            if (AesX86Engine.IsSupported)
                return new AesX86Engine();
#endif

            return new AesEngine();
        }
    }
}
