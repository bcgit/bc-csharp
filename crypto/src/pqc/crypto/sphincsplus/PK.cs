namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class PK
    {
        internal byte[] seed;
        internal byte[] root;

        internal PK(byte[] seed, byte[] root)
        {
            this.seed = seed;
            this.root = root;
        }
    }
}
