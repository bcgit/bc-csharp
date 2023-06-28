namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class SIG_XMSS
    {
        internal byte[] sig;
        internal byte[][] auth;

        internal SIG_XMSS(byte[] sig, byte[][] auth)
        {
            this.sig = sig;
            this.auth = auth;
        }

        internal byte[] WotsSig => sig;

        internal byte[][] XmssAuth => auth;
    }
}
