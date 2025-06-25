using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature object</remarks>
    public class OnePassSignaturePacket
		: ContainedPacket
	{
		private int version;
		private int sigType;
		private HashAlgorithmTag hashAlgorithm;
		private PublicKeyAlgorithmTag keyAlgorithm;
		private long keyId;
		private int nested;

		internal OnePassSignaturePacket(
			BcpgInputStream	bcpgIn)
		{
			version = bcpgIn.RequireByte();
			sigType = bcpgIn.RequireByte();
			hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();
			keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
			keyId = (long)StreamUtilities.RequireUInt64BE(bcpgIn);
			nested = bcpgIn.RequireByte();
		}

		public OnePassSignaturePacket(
			int						sigType,
			HashAlgorithmTag		hashAlgorithm,
			PublicKeyAlgorithmTag	keyAlgorithm,
			long					keyId,
			bool					isNested)
		{
			this.version = 3;
			this.sigType = sigType;
			this.hashAlgorithm = hashAlgorithm;
			this.keyAlgorithm = keyAlgorithm;
			this.keyId = keyId;
			this.nested = (isNested) ? 0 : 1;
		}

		public int SignatureType
		{
			get { return sigType; }
		}

		/// <summary>The encryption algorithm tag.</summary>
		public PublicKeyAlgorithmTag KeyAlgorithm
		{
			get { return keyAlgorithm; }
		}

		/// <summary>The hash algorithm tag.</summary>
		public HashAlgorithmTag HashAlgorithm
		{
			get { return hashAlgorithm; }
		}

		/// <remarks>
		/// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
		/// </remarks>
		public long KeyId => keyId;

		public override void Encode(BcpgOutputStream bcpgOut)
		{
			MemoryStream bOut = new MemoryStream();
			using (var pOut = new BcpgOutputStream(bOut))
            {
				pOut.Write((byte)version, (byte)sigType, (byte)hashAlgorithm, (byte)keyAlgorithm);
				pOut.WriteLong(keyId);
				pOut.WriteByte((byte)nested);
			}

			bcpgOut.WritePacket(PacketTag.OnePassSignature, bOut.ToArray());
		}
	}
}
