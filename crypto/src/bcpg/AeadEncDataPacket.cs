using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /**
     * Packet representing AEAD encrypted data. At the moment this appears to exist in the following
     * expired draft only, but it's appearing despite this.
     *
     * @ref https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16
     */
    public class AeadEncDataPacket
        : InputStreamPacket
    {
        private readonly byte m_version;
        private readonly SymmetricKeyAlgorithmTag m_algorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly byte m_chunkSize;
        private readonly byte[] m_iv;

        public AeadEncDataPacket(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
            m_version = bcpgIn.RequireByte();
            if (m_version != 1)
                throw new ArgumentException("wrong AEAD packet version: " + m_version);

            m_algorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
            m_aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.RequireByte();
            m_chunkSize = bcpgIn.RequireByte();

            m_iv = new byte[GetIVLength(m_aeadAlgorithm)];
            bcpgIn.ReadFully(m_iv);
        }

        public AeadEncDataPacket(SymmetricKeyAlgorithmTag algorithm, AeadAlgorithmTag aeadAlgorithm, int chunkSize,
            byte[] iv)
            : base(null)
        {
            m_version = 1;
            m_algorithm = algorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_chunkSize = (byte)chunkSize;
            m_iv = Arrays.Clone(iv);
        }

        public byte Version => m_version;

        public SymmetricKeyAlgorithmTag Algorithm => m_algorithm;

        public AeadAlgorithmTag AeadAlgorithm => m_aeadAlgorithm;

        public int ChunkSize => m_chunkSize;

        public byte[] GetIV() => m_iv;

        public static int GetIVLength(AeadAlgorithmTag aeadAlgorithm)
        {
            switch (aeadAlgorithm)
            {
            case AeadAlgorithmTag.Eax:
                return 16;
            case AeadAlgorithmTag.Ocb:
                return 15;
            case AeadAlgorithmTag.Gcm:
                return 12;
            default:
                throw new ArgumentException("unknown mode: " + aeadAlgorithm);
            }
        }
    }
}
