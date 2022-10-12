using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    public class RandUtils
    {
        public static int NextInt(SecureRandom rand, int n)
        {

            if ((n & -n) == n)  // i.e., n is a power of 2
            {
                return (int)((n * (long)(Utils.UnsignedRightBitShiftInt(rand.NextInt(), 1))) >> 31);
            }

            int bits, value;
            do
            {
                bits = Utils.UnsignedRightBitShiftInt(rand.NextInt() ,1);
                value = bits % n;
            }
            while (bits - value + (n - 1) < 0);

            return value;
        }
    }

}
