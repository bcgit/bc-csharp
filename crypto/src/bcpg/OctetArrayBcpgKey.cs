using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Public/Secret IBcpgKey which is encoded as an array of octets rather than an MPI.</summary>
    public abstract class OctetArrayBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly byte[] m_key;

        internal OctetArrayBcpgKey(int length, BcpgInputStream bcpgIn)
        {
            if (length > PublicKeyPacket.MaxLength)
                throw new IOException($"Max key length ({PublicKeyPacket.MaxLength}) exceeded ({length})");

            m_key = new byte[length];
            bcpgIn.ReadFully(m_key);
        }

        internal OctetArrayBcpgKey(int length, byte[] key)
        {
            if (key.Length != length)
                throw new ArgumentException($"unexpected key encoding length: expected {length} bytes, got {key.Length}");

            m_key = new byte[length];
            Array.Copy(key, 0, m_key, 0, length);
        }

        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.Write(m_key);

        public virtual string Format => "PGP";

        public override byte[] GetEncoded()
        {
            try
            {
                return base.GetEncoded();
            }
            catch (IOException)
            {
                return null;
            }
        }

        public virtual byte[] GetKey() => Arrays.Clone(m_key);

        internal virtual byte[] Key => m_key;
    }
}
