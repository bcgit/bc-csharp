namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal static class Reduce
    {
        public static int MontgomeryReduce(long a)
        {
            int t = (int)(a * MLDsaEngine.QInv);
            return (int)((a - (long)t * MLDsaEngine.Q) >> 32);
        }

        public static int Reduce32(int a)
        {
            int t = (a + (1 << 22)) >> 23;
            return a - t * MLDsaEngine.Q;
        }

        public static int ConditionalAddQ(int a) => a + ((a >> 31) & MLDsaEngine.Q);
    }
}
