using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>
    /// Crypto functions for XMSS: the keyed hash functions F, H, H_msg and PRF of RFC 8391 sec. 4.1.2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each of them hashes <c>toByte(i, n) || key || in</c> under its own domain separator i, and that
    /// concatenation carries no length prefix - so it is unambiguous only because every argument has the fixed
    /// length RFC 8391 sec. 4.1.2 gives it: F an n-byte key and an n-byte string, H an n-byte key and a 2n-byte
    /// string, H_msg a 3n-byte key and a message of any length, PRF an n-byte key and a 32-byte index.
    /// </para>
    /// <para>
    /// Those lengths are guaranteed by the call sites rather than checked here. A new call site has to keep that
    /// true: a wrong length is not rejected here, it silently hashes to something else.
    /// </para>
    /// <para>
    /// The digest size is likewise taken to be at most the underlying digest's own output size; the admissible
    /// (digest, n) pairs are fixed by <see cref="WotsPlusOid"/>.
    /// </para>
    /// </remarks>
    internal sealed class KeyedHashFunctions
    {
        /// <summary>
        /// The largest tree digest size <see cref="WotsPlusOid"/> admits, that being SHA-512's and SHAKE256's 64.
        /// </summary>
        private const int MaxTreeDigestSize = 64;

        /// <summary>
        /// toByte(i, n) for the four domain separators: each is n - 1 zero bytes followed by i, so one table
        /// serves every n, toByte(i, n) being the last n bytes of toByte(i, MaxTreeDigestSize). Only ever read.
        /// </summary>
        private static readonly byte[][] ToByte = CreateToByte();

        private static byte[][] CreateToByte()
        {
            byte[][] toByte = new byte[4][];
            for (int i = 0; i != toByte.Length; i++)
            {
                toByte[i] = new byte[MaxTreeDigestSize];
                toByte[i][MaxTreeDigestSize - 1] = (byte)i;
            }
            return toByte;
        }

        private readonly IDigest m_digest;
        private readonly int m_digestSize;

        internal KeyedHashFunctions(DerObjectIdentifier treeDigest, int digestSize)
        {
            m_digest = XmssDigestUtilities.GetDigest(treeDigest);
            m_digestSize = digestSize;
        }

        private byte[] CoreDigest(int fixedValue, byte[] key, byte[] index)
        {
            byte[] output = new byte[m_digestSize];
            CoreDigest(fixedValue, key, index, output, 0);
            return output;
        }

        private void CoreDigest(int fixedValue, byte[] key, byte[] index, byte[] output, int outOff)
        {
            /* fill first n byte of out buffer */
            m_digest.BlockUpdate(ToByte[fixedValue], MaxTreeDigestSize - m_digestSize, m_digestSize);
            /* add key */
            m_digest.BlockUpdate(key, 0, key.Length);
            /* add index */
            m_digest.BlockUpdate(index, 0, index.Length);

            if (m_digest is IXof xof)
            {
                xof.OutputFinal(output, outOff, m_digestSize);
            }
            else if (m_digestSize < m_digest.GetDigestSize())
            {
                byte[] full = new byte[m_digest.GetDigestSize()];
                m_digest.DoFinal(full, 0);
                Array.Copy(full, 0, output, outOff, m_digestSize);
                // a PRF output passing through here can be secret key material
                Arrays.ZeroMemory(full);
            }
            else
            {
                m_digest.DoFinal(output, outOff);
            }
        }

        internal void F(byte[] key, byte[] input, byte[] output) => CoreDigest(0, key, input, output, 0);

        internal void H(byte[] key, byte[] input, byte[] output) => CoreDigest(1, key, input, output, 0);

        internal byte[] HMsg(byte[] key, byte[] input) => CoreDigest(2, key, input);

        internal byte[] Prf(byte[] key, byte[] address) => CoreDigest(3, key, address);

        internal void Prf(byte[] key, byte[] address, byte[] output) => CoreDigest(3, key, address, output, 0);

        internal void Prf(byte[] key, byte[] address, byte[] output, int outOff) =>
            CoreDigest(3, key, address, output, outOff);
    }
}
