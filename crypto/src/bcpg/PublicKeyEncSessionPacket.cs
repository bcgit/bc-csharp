using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for a PGP public key.</remarks>
	public class PublicKeyEncSessionPacket
		: ContainedPacket //, PublicKeyAlgorithmTag
	{
        private readonly int version;						// V3, V6
        private readonly long keyId;                        // V3 only
        private readonly PublicKeyAlgorithmTag algorithm;	// V3, V6
        private readonly byte[][] data;						// V3, V6
        private readonly int keyVersion;					// V6 only
        private readonly byte[] keyFingerprint;				// V6 only

        /// <summary>
        /// Version 3 PKESK packet.
        /// </summary>
        /// <seealso href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-3-public-key-encryp"/>
        public const int Version3 = 3;

        /// <summary>
        /// Version 6 PKESK packet.
        /// </summary>
		/// <seealso href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-6-public-key-encryp"/>
        public const int Version6 = 6;

        internal PublicKeyEncSessionPacket(
			BcpgInputStream bcpgIn)
			:base(PacketTag.PublicKeyEncryptedSession)
		{
			version = bcpgIn.ReadByte();
            switch (version)
			{
                case Version3:
                    keyId |= (long)bcpgIn.ReadByte() << 56;
                    keyId |= (long)bcpgIn.ReadByte() << 48;
                    keyId |= (long)bcpgIn.ReadByte() << 40;
                    keyId |= (long)bcpgIn.ReadByte() << 32;
                    keyId |= (long)bcpgIn.ReadByte() << 24;
                    keyId |= (long)bcpgIn.ReadByte() << 16;
                    keyId |= (long)bcpgIn.ReadByte() << 8;
                    keyId |= (uint)bcpgIn.ReadByte();
                    break;
                case Version6:
                    int keyInfoLength = bcpgIn.ReadByte();
                    if (keyInfoLength == 0)
                    {
                        // anonymous recipient
                        keyVersion = 0;
                        keyFingerprint = Array.Empty<byte>();
                        keyId = 0;
                    }
                    else
                    {
                        keyVersion = bcpgIn.ReadByte();
                        keyFingerprint = new byte[keyInfoLength - 1];
                        bcpgIn.ReadFully(keyFingerprint);

                        switch (keyVersion)
                        {
                            case PublicKeyPacket.Version4:
                                keyId = (long)Pack.BE_To_UInt64(keyFingerprint, keyFingerprint.Length - 8);
                                break;
                            case PublicKeyPacket.Version5:
                            case PublicKeyPacket.Version6:
                                keyId = (long)Pack.BE_To_UInt64(keyFingerprint);
                                break;
                            default:
                                throw new InvalidOperationException($"unsupported OpenPGP key packet version: {keyVersion}");
                        }
                    }
                    break;
                default:
                    throw new UnsupportedPacketVersionException($"Unsupported PGP public key encrypted session key packet version encountered: {version}");
            }
			
			algorithm = (PublicKeyAlgorithmTag) bcpgIn.ReadByte();

            switch (algorithm)
			{
				case PublicKeyAlgorithmTag.RsaEncrypt:
				case PublicKeyAlgorithmTag.RsaGeneral:
					data = new byte[][]{ new MPInteger(bcpgIn).GetEncoded() };
					break;
				case PublicKeyAlgorithmTag.ElGamalEncrypt:
				case PublicKeyAlgorithmTag.ElGamalGeneral:
                    MPInteger p = new MPInteger(bcpgIn);
                    MPInteger g = new MPInteger(bcpgIn);
					data = new byte[][]{
                        p.GetEncoded(),
                        g.GetEncoded(),
                    };
					break;
                case PublicKeyAlgorithmTag.ECDH:
                    data = new byte[][]{ Streams.ReadAll(bcpgIn) };
                    break;
                case PublicKeyAlgorithmTag.X25519:
                case PublicKeyAlgorithmTag.X448:
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-x

                    // 32 (for X25519) or 56 (for X448) octets representing an ephemeral public key.
                    int keylen = algorithm == PublicKeyAlgorithmTag.X25519 ? 32 : 56;
                    byte[] ephemeralPubKey = new byte[keylen];
                    bcpgIn.ReadFully(ephemeralPubKey);

                    // A one-octet size of the following fields.
                    int esklen = bcpgIn.ReadByte();

                    // The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
                    // The encrypted session key.
                    byte[] encryptedSessionKey = new byte[esklen];
                    bcpgIn.ReadFully(encryptedSessionKey);

                    data = new byte[][]{
                        ephemeralPubKey,
                        encryptedSessionKey,
                    };
                    break;

                default:
					throw new IOException("unknown PGP public key algorithm encountered");
			}
		}


        /// <summary>
        /// Create a new V3 PKESK packet.
        /// </summary>
        /// <param name="keyId">ID of the recipient key, 0 for anonymo</param>
        /// <param name="algorithm">public key algorithm</param>
        /// <param name="data">session data</param>
        public PublicKeyEncSessionPacket(
			long                    keyId,
			PublicKeyAlgorithmTag   algorithm,
			byte[][]                data)
            : base(PacketTag.PublicKeyEncryptedSession)
        {
			this.version = Version3;
			this.keyId = keyId;
			this.algorithm = algorithm;
            this.data = new byte[data.Length][];
            for (int i = 0; i < data.Length; ++i)
            {
                this.data[i] = Arrays.Clone(data[i]);
            }
		}

        /// <summary>
        /// Create a new V6 PKESK packet.
        /// </summary>
        /// <param name="keyVersion">version of the key</param>
        /// <param name="keyFingerprint">fingerprint of the key</param>
        /// <param name="algorithm">public key algorith</param>
        /// <param name="data">session data</param>
        public PublicKeyEncSessionPacket(
            int keyVersion,
            byte[] keyFingerprint,
            PublicKeyAlgorithmTag algorithm,
            byte[][] data)
            : base(PacketTag.PublicKeyEncryptedSession)
        {
            this.version = Version6;
            this.keyVersion = keyVersion;
            this.keyFingerprint = Arrays.Clone(keyFingerprint);
            this.algorithm = algorithm;
            this.data = new byte[data.Length][];

            for (int i = 0; i < data.Length; i++)
            {
                this.data[i] = Arrays.Clone(data[i]);
            }
        }

        public int Version
		{
			get { return version; }
		}

		public long KeyId
		{
			get { return keyId; }
		}

        public bool IsRecipientAnonymous
        {
            get { return keyId == 0; }
        }

        public byte[] GetKeyFingerprint()
        {
            return Arrays.Clone(keyFingerprint);
        }

        public int KeyVersion
        {
            get { return keyVersion; }
        }

        public PublicKeyAlgorithmTag Algorithm
		{
			get { return algorithm; }
		}

        public byte[][] GetEncSessionKey()
		{
			return data;
		}

        public override void Encode(BcpgOutputStream bcpgOut)
		{
            using (MemoryStream bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {
                    pOut.WriteByte((byte)version);

                    switch (version)
                    {
                        case Version3:
                            pOut.WriteLong(keyId);
                            break;

                        case Version6:
                            if (keyVersion == 0)
                            {
                                // anonymous recipient
                                pOut.WriteByte(0);
                            }
                            else
                            {
                                pOut.WriteByte((byte)(keyFingerprint.Length + 1));
                                pOut.WriteByte((byte)keyVersion);
                                pOut.Write(keyFingerprint);
                            }
                            break;
                        default:
                            throw new UnsupportedPacketVersionException($"Unsupported PGP public key encrypted session key packet version encountered: {version}");
                    }

                    pOut.WriteByte((byte)algorithm);

                    if (algorithm == PublicKeyAlgorithmTag.X25519 || algorithm == PublicKeyAlgorithmTag.X448)
                    {
                        // ephemeral public key.
                        pOut.Write(data[0]);
                        // One-octet size of the encrypted session key (prefixed by the one-octet
                        // algorithm identifier, in the case of a v3 PKESK packet).
                        pOut.WriteByte((byte)(data[1].Length));
                        // encrypted session key
                        pOut.Write(data[1]);
                    }
                    else
                    {
                        for (int i = 0; i < data.Length; ++i)
                        {
                            pOut.Write(data[i]);
                        }
                    }
                }

                bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession, bOut.ToArray());
            }
		}
	}
}
