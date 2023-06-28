using System;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    [Obsolete("Will be removed")]
    public class BasicGcmMultiplier
        : IGcmMultiplier
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsHardwareAccelerated => Pclmulqdq.IsSupported;
#else
        internal static bool IsHardwareAccelerated => false;
#endif

        private GcmUtilities.FieldElement H;

        public void Init(byte[] H)
        {
            GcmUtilities.AsFieldElement(H, out this.H);
        }

        public void MultiplyH(byte[] x)
        {
            GcmUtilities.AsFieldElement(x, out var T);
            GcmUtilities.Multiply(ref T, ref H);
            GcmUtilities.AsBytes(ref T, x);
        }
    }
}
