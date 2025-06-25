using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyEncSessionPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private readonly int m_version;
        private readonly long m_keyID;
        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly byte[][] m_data;

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {
            m_version = bcpgIn.RequireByte();
            m_keyID = (long)StreamUtilities.RequireUInt64BE(bcpgIn);
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
        {
            m_version = 3;
            m_keyID = keyId;
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
        public long KeyId => m_keyID;

        public PublicKeyAlgorithmTag Algorithm => m_algorithm;

        public byte[][] GetEncSessionKey() => m_data;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte((byte)m_version);
                pOut.WriteLong(m_keyID);
                pOut.WriteByte((byte)m_algorithm);

                for (int i = 0; i < m_data.Length; ++i)
                {
                    pOut.Write(m_data[i]);
                }
            }

            bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession, bOut.ToArray());
        }
    }
}
