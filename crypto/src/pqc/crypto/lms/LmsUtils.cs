using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public static class LmsUtilities
    {
        public static void U32Str(int n, IDigest d)
        {
            d.Update((byte)(n >> 24));
            d.Update((byte)(n >> 16));
            d.Update((byte)(n >> 8));
            d.Update((byte)(n));
        }

        public static void U16Str(ushort n, IDigest d)
        {
            d.Update((byte)(n >> 8));
            d.Update((byte)(n));
        }

        public static void ByteArray(byte[] array, IDigest digest)
        {
            digest.BlockUpdate(array, 0, array.Length);
        }

        public static void ByteArray(byte[] array, int start, int len, IDigest digest)
        {
            digest.BlockUpdate(array, start, len);
        }

        public static int CalculateStrength(LmsParameters lmsParameters)
        {
            if (lmsParameters == null)
                throw new ArgumentNullException(nameof(lmsParameters));

            LMSigParameters sigParameters = lmsParameters.LMSigParameters;
            return sigParameters.M << sigParameters.H;
        }
    }
}
