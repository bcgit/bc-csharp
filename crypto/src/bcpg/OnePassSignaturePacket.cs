using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature object</remarks>
    public class OnePassSignaturePacket
		: ContainedPacket
	{
        public const int Version3 = 3;
        public const int Version6 = 6;

        private readonly int version;
		private readonly int sigType;
		private readonly HashAlgorithmTag hashAlgorithm;
        private readonly PublicKeyAlgorithmTag keyAlgorithm;
        private readonly long keyId;
		private readonly int nested;

		// fields for V6
		private readonly byte[] salt;
		private readonly byte[] fingerprint;

		private void EnforceConstraints()
		{
			int expectedSaltSize = PgpUtilities.GetSaltSize(hashAlgorithm);

            if (version == Version6 && salt.Length != expectedSaltSize)
            {
                // https://www.rfc-editor.org/rfc/rfc9580#name-one-pass-signature-packet-t
                // The salt size MUST match the value defined for the hash algorithm as specified in Table 23
                // https://www.rfc-editor.org/rfc/rfc9580#hash-algorithms-registry
                throw new IOException($"invalid salt size for v6 signature: expected {expectedSaltSize} got {salt.Length}");
            }
        }

        internal OnePassSignaturePacket(
			BcpgInputStream	bcpgIn)
			:base(PacketTag.OnePassSignature)
		{
			version = bcpgIn.RequireByte();
			if (version != Version3 && version != Version6)
			{
                throw new UnsupportedPacketVersionException($"unsupported OpenPGP One Pass Signature packet version: {version}");
            }

			sigType = bcpgIn.RequireByte();
			hashAlgorithm = (HashAlgorithmTag) bcpgIn.RequireByte();
			keyAlgorithm = (PublicKeyAlgorithmTag) bcpgIn.RequireByte();

            if (version == Version3)
			{
				keyId = (long)StreamUtilities.RequireUInt64BE(bcpgIn);
            }
			else
			{
                //Version 6
                int saltSize = bcpgIn.ReadByte();
                salt = new byte[saltSize];
                bcpgIn.ReadFully(salt);

				fingerprint = new byte[32];
                bcpgIn.ReadFully(fingerprint);
				keyId = (long)Pack.BE_To_UInt64(fingerprint);
            }

			nested = bcpgIn.RequireByte();

			EnforceConstraints();
        }

		/// <summary>
		/// Create a Version 3 OPS Packet
		/// </summary>
		/// <param name="sigType"></param>
		/// <param name="hashAlgorithm"></param>
		/// <param name="keyAlgorithm"></param>
		/// <param name="keyId"></param>
		/// <param name="isNested"></param>
		public OnePassSignaturePacket(
			int						sigType,
			HashAlgorithmTag		hashAlgorithm,
			PublicKeyAlgorithmTag	keyAlgorithm,
			long					keyId,
			bool					isNested)
			: base(PacketTag.OnePassSignature)
        {
			this.version = Version3;
			this.sigType = sigType;
			this.hashAlgorithm = hashAlgorithm;
			this.keyAlgorithm = keyAlgorithm;
			this.keyId = keyId;
			this.nested = (isNested) ? 0 : 1;

            EnforceConstraints();
        }

        /// <summary>
		/// Create a Version 6 OPS Packet
		/// </summary>
		/// <param name="sigType"></param>
		/// <param name="hashAlgorithm"></param>
		/// <param name="keyAlgorithm"></param>
		/// <param name="salt"></param>
		/// <param name="fingerprint"></param>
		/// <param name="isNested"></param>
		public OnePassSignaturePacket(
			int sigType,
			HashAlgorithmTag hashAlgorithm,
			PublicKeyAlgorithmTag keyAlgorithm,
			byte[] salt,
			byte[] fingerprint,
			bool isNested)
			: base(PacketTag.OnePassSignature)
        {
            this.version = Version6;
            this.sigType = sigType;
            this.hashAlgorithm = hashAlgorithm;
            this.keyAlgorithm = keyAlgorithm;
            this.salt = Arrays.Clone(salt);
            this.fingerprint = Arrays.Clone(fingerprint);
            this.keyId = (long)Pack.BE_To_UInt64(fingerprint);
            this.nested = (isNested) ? 0 : 1;

            EnforceConstraints();
        }

		public int Version {
			get { return version; }
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

		public long KeyId
		{
			get { return keyId; }
		}

        public byte[] GetFingerprint()
        {
			return Arrays.Clone(fingerprint);
        }

        public byte[] GetSignatureSalt()
        {
            return Arrays.Clone(salt);
        }

        public override void Encode(BcpgOutputStream bcpgOut)
		{
			using (MemoryStream bOut = new MemoryStream())
			{
				using (var pOut = new BcpgOutputStream(bOut))
				{
					pOut.Write((byte)version, (byte)sigType, (byte)hashAlgorithm, (byte)keyAlgorithm);

					if (version == Version3)
					{
						pOut.WriteLong(keyId);
					}
					else
					{
						// V6
						pOut.WriteByte((byte)salt.Length);
						pOut.Write(salt);
                        pOut.Write(fingerprint);
                    }
					pOut.WriteByte((byte)nested);
				}

				bcpgOut.WritePacket(PacketTag.OnePassSignature, bOut.ToArray());
			}
		}
	}
}
