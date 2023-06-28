namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class SIG_FORS
    {
        internal byte[][] authPath;
        internal byte[] sk;

        internal SIG_FORS(byte[] sk, byte[][] authPath)
        {
            this.authPath = authPath;
            this.sk = sk;
        }

        public byte[] SK => sk;

        public byte[][] AuthPath => authPath;
    }
}
