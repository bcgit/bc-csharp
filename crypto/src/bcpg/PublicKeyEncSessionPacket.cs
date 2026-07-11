using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a PGP public key.</summary>
    public class PublicKeyEncSessionPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        /// <summary>Version 3 PKESK packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricEncIntegrityPacket.Version1">V1 SEIPD</see> or
        /// <see cref="SymmetricEncDataPacket">SED</see> packets.
        /// </remarks>
        public const int Version3 = 3;

        /// <summary>Version 6 PKESK packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricEncIntegrityPacket.Version2">V2 SEIPD</see> packets.
        /// </remarks>
        public const int Version6 = 6;

        private readonly int m_version;
        private readonly ulong m_keyID;
        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly byte[][] m_data;

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.PublicKeyEncryptedSession, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
            m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
            m_algorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();

            switch (m_algorithm)
            {
            case PublicKeyAlgorithmTag.RsaEncrypt:
            case PublicKeyAlgorithmTag.RsaGeneral:
                m_data = new byte[][]{ new MPInteger(bcpgIn).GetEncoded() };
                break;
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                MPInteger p = new MPInteger(bcpgIn);
                MPInteger g = new MPInteger(bcpgIn);
                m_data = new byte[][]{
                    p.GetEncoded(),
                    g.GetEncoded(),
                };
                break;
            case PublicKeyAlgorithmTag.ECDH:
                m_data = new byte[][]{ Streams.ReadAll(bcpgIn) };
                break;
            default:
                throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        public PublicKeyEncSessionPacket(long keyId, PublicKeyAlgorithmTag algorithm, byte[][] data)
            : base(PacketTag.PublicKeyEncryptedSession)
        {
            m_version = 3;
            m_keyID = (ulong)keyId;
            m_algorithm = algorithm;
            m_data = new byte[data.Length][];
            for (int i = 0; i < data.Length; ++i)
            {
                m_data[i] = Arrays.Clone(data[i]);
            }
        }

        public int Version => m_version;

        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        public PublicKeyAlgorithmTag Algorithm => m_algorithm;

        public byte[][] GetEncSessionKey() => m_data;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            uint bodyLength = 1U + 8U + 1U;
            foreach (var data in m_data)
            {
                bodyLength += (uint)data.Length;
            }

            bcpgOut.WritePacketHeader(HasNewPacketFormat, PacketTag.PublicKeyEncryptedSession, bodyLength);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> body = stackalloc byte[10];
#else
            byte[] body = new byte[10];
#endif

            body[0] = (byte)m_version;
            Pack.UInt64_To_BE(m_keyID, body, 1);
            body[9] = (byte)m_algorithm;

            bcpgOut.Write(body);

            foreach (var data in m_data)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                bcpgOut.Write(data.AsSpan());
#else
                bcpgOut.Write(data, 0, data.Length);
#endif
            }
        }
    }
}
