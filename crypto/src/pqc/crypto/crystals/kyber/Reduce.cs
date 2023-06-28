namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    internal static class Reduce
    {
        internal static short MontgomeryReduce(int a)
        {
            short u = (short)(a * KyberEngine.QInv);
            int t = u * KyberEngine.Q;
            t = a - t;
            t >>= 16;
            return (short)t;
        }

        internal static short BarrettReduce(short a)
        {
            short v = (short)(((1U << 26) + (KyberEngine.Q / 2)) / KyberEngine.Q);
            short t = (short)((v * a) >> 26);
            t = (short)(t * KyberEngine.Q);
            return (short)(a - t);
        }

        internal static short CondSubQ(short a)
        {
            a -= KyberEngine.Q;
            a += (short)((a >> 15) & KyberEngine.Q);
            return a;
        }
    }
}
