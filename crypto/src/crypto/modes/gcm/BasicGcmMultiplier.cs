using System;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    public class BasicGcmMultiplier
        : IGcmMultiplier
    {
        private ulong[] H;

        public void Init(byte[] H)
        {
            this.H = GcmUtilities.AsUlongs(H);
        }

        public void MultiplyH(byte[] x)
        {
            ulong[] t = GcmUtilities.AsUlongs(x);
            GcmUtilities.Multiply(t, H);
            GcmUtilities.AsBytes(t, x);
        }
    }
}
