using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a symmetric encrypted session key packet.</summary>
    public class SymmetricKeyEncSessionPacket
        : ContainedPacket
    {
        private readonly int m_version;
        private readonly SymmetricKeyAlgorithmTag m_encAlgorithm;
        private readonly S2k m_s2k;
        private readonly byte[] m_secKeyData;

        public SymmetricKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {
            m_version = bcpgIn.RequireByte();
            m_encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
            m_s2k = new S2k(bcpgIn);
            m_secKeyData = bcpgIn.ReadAll();
        }

        public SymmetricKeyEncSessionPacket(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] secKeyData)
        {
            m_version = 4;
            m_encAlgorithm = encAlgorithm;
            m_s2k = s2k;
            m_secKeyData = secKeyData;
        }

        public SymmetricKeyAlgorithmTag EncAlgorithm => m_encAlgorithm;

        public S2k S2k => m_s2k;

        public byte[] GetSecKeyData() => m_secKeyData;

        public int Version => m_version;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.Write((byte)m_version, (byte)m_encAlgorithm);
                m_s2k.Encode(pOut);

                if (m_secKeyData != null && m_secKeyData.Length > 0)
                {
                    pOut.Write(m_secKeyData);
                }
            }

            bcpgOut.WritePacket(PacketTag.SymmetricKeyEncryptedSessionKey, bOut.ToArray());
        }
    }
}
