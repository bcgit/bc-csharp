namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class Reduce
    {
        public static int MontgomeryReduce(long a)
        {
            int t = (int)(a * DilithiumEngine.QInv);
            return (int)((a - (long)t * DilithiumEngine.Q) >> 32);
        }

        public static int Reduce32(int a)
        {
            int t = (a + (1 << 22)) >> 23;
            return a - t * DilithiumEngine.Q;
        }

        public static int ConditionalAddQ(int a) => a + ((a >> 31) & DilithiumEngine.Q);
    }
}
