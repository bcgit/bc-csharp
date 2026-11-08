using System;

using Org.BouncyCastle.Crypto.Signers.Xmss;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>The wire form an XMSS and an XMSS^MT public key share.</summary>
    /// <remarks>
    /// RFC 8391 sec. 4.1.7 and sec. 4.2.5 give the two the same shape - root followed by SEED, both n bytes - and
    /// NIST SP 800-208 sec. 5 puts a four byte parameter set identifier in front of each, so the encoding differs
    /// between the families only in which parameter set the identifier names. <see cref="Resolve"/> is the rule for
    /// how a key resolves its three fields, from an encoding or from the fields themselves.
    /// </remarks>
    internal sealed class XmssPublicKeyCodec
    {
        /// <summary>
        /// The width of the SP 800-208 parameter set identifier. Zero is not a registered value, so it is what a key
        /// written before the identifier existed is given, and a key carrying it is encoded without one.
        /// </summary>
        private const int OidSize = 4;

        private readonly int m_oid;
        private readonly byte[] m_root;
        private readonly byte[] m_publicSeed;

        private XmssPublicKeyCodec(int oid, byte[] root, byte[] publicSeed)
        {
            m_oid = oid;
            m_root = root;
            m_publicSeed = publicSeed;
        }

        /// <summary>
        /// Read a public key encoding, in either the current form or the pre-RFC one that carries no parameter set
        /// identifier. Which one it is is decided by the length, so the length is checked before anything is read
        /// out of it.
        /// </summary>
        /// <param name="publicKey">the encoding.</param>
        /// <param name="n">the security parameter of the key's parameter set, in bytes.</param>
        internal static XmssPublicKeyCodec Decode(byte[] publicKey, int n)
        {
            if (publicKey.Length == n + n)
            {
                // pre-rfc final key without OID.
                return new XmssPublicKeyCodec(0, Arrays.CopyOfRange(publicKey, 0, n),
                    Arrays.CopyOfRange(publicKey, n, n + n));
            }
            if (publicKey.Length == OidSize + n + n)
            {
                return new XmssPublicKeyCodec((int)Pack.BE_To_UInt32(publicKey, 0),
                    Arrays.CopyOfRange(publicKey, OidSize, OidSize + n),
                    Arrays.CopyOfRange(publicKey, OidSize + n, OidSize + n + n));
            }

            throw new ArgumentException("public key has wrong size");
        }

        /// <summary>
        /// The three fields of a public key, from whichever of the two ways its builder was given them.
        /// </summary>
        /// <param name="publicKey">an encoding to take apart, or null when the fields were set directly.</param>
        /// <param name="n">the security parameter of the key's parameter set, in bytes.</param>
        /// <param name="parameterSetOid">the identifier the key's own parameter set carries, which is what a key
        /// built from fields records; a decoded key keeps the one its encoding named, including the zero of a key
        /// written before the identifier existed.</param>
        /// <param name="root">the root, or null to be allocated at n.</param>
        /// <param name="publicSeed">the seed, or null to be allocated at n.</param>
        internal static XmssPublicKeyCodec Resolve(byte[] publicKey, int n, int parameterSetOid, byte[] root,
            byte[] publicSeed)
        {
            if (publicKey != null)
            {
                /* import */
                XmssPublicKeyCodec decoded = Decode(publicKey, n);

                // a key that names its parameter set must name this one: the root and seed of another set would
                // otherwise be read at this one's n and written back out under the other's identifier
                if (decoded.Oid != 0 && decoded.Oid != parameterSetOid)
                    throw new ArgumentException("public key parameter set does not match the parameters");

                return decoded;
            }

            /* set */
            return new XmssPublicKeyCodec(parameterSetOid,
                XmssEngine.ValidateOrAllocate(root, n, "root"),
                XmssEngine.ValidateOrAllocate(publicSeed, n, "publicSeed"));
        }

        /// <summary>
        /// The encoding of a key holding these fields: oid || root || seed, with the oid omitted when it is zero.
        /// </summary>
        internal static byte[] Encode(int oid, byte[] root, byte[] publicSeed)
        {
            /* oid || root || seed */
            int oidSize = (oid != 0) ? OidSize : 0;
            byte[] output = new byte[oidSize + root.Length + publicSeed.Length];
            int position = 0;

            /* copy oid */
            if (oid != 0)
            {
                Pack.UInt32_To_BE((uint)oid, output, position);
                position += OidSize;
            }
            /* copy root */
            Array.Copy(root, 0, output, position, root.Length);
            position += root.Length;
            /* copy public seed */
            Array.Copy(publicSeed, 0, output, position, publicSeed.Length);

            return output;
        }

        internal int Oid => m_oid;

        internal byte[] Root => m_root;

        internal byte[] PublicSeed => m_publicSeed;
    }
}
