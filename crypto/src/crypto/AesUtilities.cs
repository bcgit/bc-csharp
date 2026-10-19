using Org.BouncyCastle.Crypto.Engines;

namespace Org.BouncyCastle.Crypto
{
    public static class AesUtilities
    {
        public static IBlockCipher CreateEngine()
        {
#if NETCOREAPP3_0_OR_GREATER
            if (IsHardwareAccelerated)
                return new AesEngine_X86();
#endif

            return new AesEngine();
        }

#if NETCOREAPP3_0_OR_GREATER
        /// <summary>Gets a value indicating whether this is hardware accelerated.</summary>
        public static bool IsHardwareAccelerated => AesEngine_X86.IsSupported;
#else
        /// <summary>Gets a value indicating whether this is hardware accelerated.</summary>
        public static bool IsHardwareAccelerated => false;
#endif
    }
}
