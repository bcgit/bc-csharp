using System;
using System.IO;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP secret key.</remarks>
    public class SecretKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
		public const int UsageNone = 0x00;
		public const int UsageChecksum = 0xff;
		public const int UsageSha1 = 0xfe;
        public const int UsageAead = 0xfd;


        private readonly PublicKeyPacket pubKeyPacket;
        private readonly byte[] secKeyData;
		private readonly int s2kUsage;
		private readonly SymmetricKeyAlgorithmTag encAlgorithm;
        private readonly S2k s2k;
        private readonly byte[] iv;
        private readonly AeadAlgorithmTag aeadAlgo;

        internal SecretKeyPacket(
            BcpgInputStream bcpgIn)
        {
			if (this is SecretSubkeyPacket)
			{
				pubKeyPacket = new PublicSubkeyPacket(bcpgIn);
			}
			else
			{
				pubKeyPacket = new PublicKeyPacket(bcpgIn);
			}

			s2kUsage = bcpgIn.ReadByte();

            if (s2kUsage != UsageNone && pubKeyPacket.Version == PublicKeyPacket.Version6)
            {
                // TODO: Use length to parse unknown parameters
                int conditionalParameterLength = bcpgIn.ReadByte();
            }

            if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1 || s2kUsage == UsageAead)
            {
                encAlgorithm = (SymmetricKeyAlgorithmTag) bcpgIn.ReadByte();
                if (s2kUsage == UsageAead)
                {
                    aeadAlgo = (AeadAlgorithmTag)bcpgIn.ReadByte();
                }
                if (pubKeyPacket.Version == 6 && (s2kUsage == UsageSha1 || s2kUsage == UsageAead))
                {
                    // TODO: Use length to parse unknown S2Ks
                    int s2kLen = bcpgIn.ReadByte();
                }
                s2k = new S2k(bcpgIn);
            }
            else
            {
                encAlgorithm = (SymmetricKeyAlgorithmTag) s2kUsage;
            }

            if (!(s2k != null && s2k.Type == S2k.GnuDummyS2K && s2k.ProtectionMode == 0x01))
            {
				if (s2kUsage != 0)
				{
                    if (((int) encAlgorithm) < 7)
                    {
                        iv = new byte[8];
                    }
                    else
                    {
                        iv = new byte[16];
                    }
                    bcpgIn.ReadFully(iv);
                }
            }

			secKeyData = bcpgIn.ReadAll();
        }

		public SecretKeyPacket(
            PublicKeyPacket				pubKeyPacket,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            S2k							s2k,
            byte[]						iv,
            byte[]						secKeyData)
        {
            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;

			if (encAlgorithm != SymmetricKeyAlgorithmTag.Null)
			{
				this.s2kUsage = UsageChecksum;
			}
			else
			{
				this.s2kUsage = UsageNone;
			}

			this.s2k = s2k;
			this.iv = Arrays.Clone(iv);
			this.secKeyData = secKeyData;
        }

		public SecretKeyPacket(
			PublicKeyPacket				pubKeyPacket,
			SymmetricKeyAlgorithmTag	encAlgorithm,
			int							s2kUsage,
			S2k							s2k,
			byte[]						iv,
			byte[]						secKeyData)
		{
			this.pubKeyPacket = pubKeyPacket;
			this.encAlgorithm = encAlgorithm;
			this.s2kUsage = s2kUsage;
			this.s2k = s2k;
			this.iv = Arrays.Clone(iv);
			this.secKeyData = secKeyData;
		}

		public SymmetricKeyAlgorithmTag EncAlgorithm
        {
			get { return encAlgorithm; }
        }

		public int S2kUsage
		{
			get { return s2kUsage; }
		}

		public byte[] GetIV()
        {
            return Arrays.Clone(iv);
        }

		public S2k S2k
        {
			get { return s2k; }
        }

		public PublicKeyPacket PublicKeyPacket
        {
			get { return pubKeyPacket; }
        }

		public byte[] GetSecretKeyData()
        {
            return secKeyData;
        }

		public byte[] GetEncodedContents()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.Write(pubKeyPacket.GetEncodedContents());
                pOut.WriteByte((byte)s2kUsage);

                if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1)
                {
                    pOut.WriteByte((byte)encAlgorithm);
                    pOut.WriteObject(s2k);
                }

                if (iv != null)
                {
                    pOut.Write(iv);
                }

                if (secKeyData != null && secKeyData.Length > 0)
                {
                    pOut.Write(secKeyData);
                }
            }
            return bOut.ToArray();
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.SecretKey, GetEncodedContents());
        }
    }
}
