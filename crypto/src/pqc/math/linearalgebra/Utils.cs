
namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    class Utils
    {
        internal static int UnsignedRightBitShiftInt(int a, int b)
        {
            uint tmp = (uint) a;
            tmp >>= b;
            return (int) tmp;
        }

        internal static long UnsignedRightBitShiftLong(long a, int b)
        {
            ulong tmp = (ulong)a;
            tmp >>= b;
            return (long) tmp;
        }
    }
}
