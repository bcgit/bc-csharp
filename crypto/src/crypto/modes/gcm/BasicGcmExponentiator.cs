using System;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    [Obsolete("Will be removed")]
    public class BasicGcmExponentiator
        : IGcmExponentiator
    {
        private GcmUtilities.FieldElement x;

        public void Init(byte[] x)
        {
            GcmUtilities.AsFieldElement(x, out this.x);
        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ExponentiateX(long pow, byte[] output)
        {
            ExponentiateX(pow, output.AsSpan());
        }
        public void ExponentiateX(long pow, Span<byte> output)
#else
        public void ExponentiateX(long pow, byte[] output)
#endif
        {
            GcmUtilities.FieldElement y;
            GcmUtilities.One(out y);

            if (pow > 0)
            {
                GcmUtilities.FieldElement powX = x;
                do
                {
                    if ((pow & 1L) != 0)
                    {
                        GcmUtilities.Multiply(ref y, ref powX);
                    }
                    GcmUtilities.Square(ref powX);
                    pow >>= 1;
                }
                while (pow > 0);
            }

            GcmUtilities.AsBytes(ref y, output);
        }
    }
}
