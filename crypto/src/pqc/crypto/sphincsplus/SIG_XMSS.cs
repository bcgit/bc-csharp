using System;

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

        internal void CopyToSignature(byte[] signature, ref int pos)
        {
            Array.Copy(sig, 0, signature, pos, sig.Length);
            pos += sig.Length;

            for (int i = 0; i < auth.Length; ++i)
            {
                Array.Copy(auth[i], 0, signature, pos, auth[i].Length);
                pos += auth[i].Length;
            }
        }

        internal byte[] WotsSig => sig;

        internal byte[][] XmssAuth => auth;
    }
}
