using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for a PGP secret key.</remarks>
    public class SecretSubkeyPacket
        : SecretKeyPacket
    {
        internal SecretSubkeyPacket(
			BcpgInputStream bcpgIn)
            : base(bcpgIn, PacketTag.SecretSubkey)
        {
        }

		public SecretSubkeyPacket(
            PublicKeyPacket				pubKeyPacket,
            SymmetricKeyAlgorithmTag	encAlgorithm,
            S2k							s2k,
            byte[]						iv,
            byte[]						secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2k, iv, secKeyData, PacketTag.SecretSubkey)
        {
        }

		public SecretSubkeyPacket(
			PublicKeyPacket				pubKeyPacket,
			SymmetricKeyAlgorithmTag	encAlgorithm,
			int							s2kUsage,
			S2k							s2k,
			byte[]						iv,
			byte[]						secKeyData)
			: base(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData, PacketTag.SecretSubkey)
		{
		}

        public SecretSubkeyPacket(
            PublicKeyPacket pubKeyPacket,
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            int s2kUsage,
            S2k s2k,
            byte[] iv,
            byte[] secKeyData)
            :base(pubKeyPacket, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, secKeyData, PacketTag.SecretSubkey)
        {
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.SecretSubkey, GetEncodedContents());
        }
    }
}
