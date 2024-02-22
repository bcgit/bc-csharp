using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a symmetric encrypted session key packet
    */
    public class SymmetricKeyEncSessionPacket
        : ContainedPacket
    {
        private readonly int version;
        private readonly SymmetricKeyAlgorithmTag encAlgorithm;
        private readonly S2k s2k;
        private readonly byte[] secKeyData;

        public SymmetricKeyEncSessionPacket(
            BcpgInputStream bcpgIn)
            :base(PacketTag.SymmetricKeyEncryptedSessionKey)
        {
            version = bcpgIn.ReadByte();
            encAlgorithm = (SymmetricKeyAlgorithmTag) bcpgIn.ReadByte();

            s2k = new S2k(bcpgIn);

            secKeyData = bcpgIn.ReadAll();
        }

		public SymmetricKeyEncSessionPacket(
            SymmetricKeyAlgorithmTag	encAlgorithm,
            S2k							s2k,
            byte[]						secKeyData)
            : base(PacketTag.SymmetricKeyEncryptedSessionKey)
        {
            this.version = 4;
            this.encAlgorithm = encAlgorithm;
            this.s2k = s2k;
            this.secKeyData = secKeyData;
        }

        /**
        * @return int
        */
        public SymmetricKeyAlgorithmTag EncAlgorithm
        {
			get { return encAlgorithm; }
        }

        /**
        * @return S2k
        */
        public S2k S2k
        {
			get { return s2k; }
        }

        /**
        * @return byte[]
        */
        public byte[] GetSecKeyData()
        {
            return secKeyData;
        }

        /**
        * @return int
        */
        public int Version
        {
			get { return version; }
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.Write((byte)version, (byte)encAlgorithm);
                pOut.WriteObject(s2k);

                if (secKeyData != null && secKeyData.Length > 0)
                {
                    pOut.Write(secKeyData);
                }
            }

			bcpgOut.WritePacket(PacketTag.SymmetricKeyEncryptedSessionKey, bOut.ToArray());
        }
    }
}
