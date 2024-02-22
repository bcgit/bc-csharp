using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Generic signature packet.</remarks>
    public class SignaturePacket
        : ContainedPacket
    {
        public const int Version2 = 2;
        public const int Version3 = 3;
        public const int Version4 = 4;
        public const int Version5 = 5;
        public const int Version6 = 6;

        private readonly int                    version;
        private readonly int                    signatureType;
        private long                            creationTime;
        private readonly long                   keyId;
        private readonly PublicKeyAlgorithmTag  keyAlgorithm;
        private readonly HashAlgorithmTag       hashAlgorithm;
        private readonly MPInteger[]            signature;
        private readonly byte[]                 fingerprint;
        private readonly SignatureSubpacket[]   hashedData;
        private readonly SignatureSubpacket[]   unhashedData;
		private readonly byte[]                 signatureEncoding;

        // fields for v6 signatures
        private readonly byte[] salt;

        internal SignaturePacket(BcpgInputStream bcpgIn)
            :base(PacketTag.Signature)
        {
            version = bcpgIn.ReadByte();

			if (version == Version2 || version == Version3)
            {
                bcpgIn.ReadByte();

				signatureType = bcpgIn.ReadByte();
                creationTime = (((long)bcpgIn.ReadByte() << 24) | ((long)bcpgIn.ReadByte() << 16)
                    | ((long)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte()) * 1000L;

				keyId |= (long)bcpgIn.ReadByte() << 56;
                keyId |= (long)bcpgIn.ReadByte() << 48;
                keyId |= (long)bcpgIn.ReadByte() << 40;
                keyId |= (long)bcpgIn.ReadByte() << 32;
                keyId |= (long)bcpgIn.ReadByte() << 24;
                keyId |= (long)bcpgIn.ReadByte() << 16;
                keyId |= (long)bcpgIn.ReadByte() << 8;
                keyId |= (uint)bcpgIn.ReadByte();

				keyAlgorithm = (PublicKeyAlgorithmTag) bcpgIn.ReadByte();
                hashAlgorithm = (HashAlgorithmTag) bcpgIn.ReadByte();
            }
            else if (version >= Version4 && version <= Version6)
            {
                signatureType = bcpgIn.ReadByte();
                keyAlgorithm = (PublicKeyAlgorithmTag) bcpgIn.ReadByte();
                hashAlgorithm = (HashAlgorithmTag) bcpgIn.ReadByte();

                int hashedLength;

                if (version == Version6)
                {
                    hashedLength = (bcpgIn.ReadByte() << 24)
                        | (bcpgIn.ReadByte() << 16)
                        | (bcpgIn.ReadByte() << 8)
                        | bcpgIn.ReadByte();
                }
                else
                {
                    hashedLength = (bcpgIn.ReadByte() << 8)
                        | bcpgIn.ReadByte();
                }
                byte[] hashed = new byte[hashedLength];

				bcpgIn.ReadFully(hashed);

				//
                // read the signature sub packet data.
                //
                SignatureSubpacketsParser sIn = new SignatureSubpacketsParser(
                    new MemoryStream(hashed, false));

                var v = new List<SignatureSubpacket>();

				SignatureSubpacket sub;
				while ((sub = sIn.ReadPacket()) != null)
                {
                    v.Add(sub);
                }

                hashedData = v.ToArray();

				foreach (var p in hashedData)
                {
                    if (p is IssuerKeyId issuerKeyId)
                    {
                        keyId = issuerKeyId.KeyId;
                    }
                    else if (p is SignatureCreationTime sigCreationTime)
                    {
                        creationTime = DateTimeUtilities.DateTimeToUnixMs(sigCreationTime.GetTime());
                    }
                }

                int unhashedLength;

                if (version == Version6)
                {
                    unhashedLength = (bcpgIn.ReadByte() << 24)
                        | (bcpgIn.ReadByte() << 16)
                        | (bcpgIn.ReadByte() << 8)
                        | bcpgIn.ReadByte();
                }
                else
                {
                    unhashedLength = (bcpgIn.ReadByte() << 8)
                        | bcpgIn.ReadByte();
                }

                byte[] unhashed = new byte[unhashedLength];

				bcpgIn.ReadFully(unhashed);

				sIn = new SignatureSubpacketsParser(new MemoryStream(unhashed, false));

				v.Clear();

				while ((sub = sIn.ReadPacket()) != null)
                {
                    v.Add(sub);
                }

                unhashedData = v.ToArray();

				foreach (var p in unhashedData)
                {
                    if (p is IssuerKeyId issuerKeyId)
                    {
                        keyId = issuerKeyId.KeyId;
                    }
                }
            }
            else
            {
                Streams.Drain(bcpgIn);

                throw new UnsupportedPacketVersionException("unsupported version: " + version);
            }

			fingerprint = new byte[2];
            bcpgIn.ReadFully(fingerprint);

            if (version == Version6)
            {
                int saltSize = bcpgIn.ReadByte();

                if (saltSize != PgpUtilities.GetSaltSize(hashAlgorithm))
                {
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-version-4-and-6-signature-p
                    // The salt size MUST match the value defined for the hash algorithm as specified in Table 23
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#hash-algorithms-registry

                    throw new IOException($"invalid salt size for v6 signature: expected {PgpUtilities.GetSaltSize(hashAlgorithm)} got {saltSize}");
                }

                salt = new byte[saltSize];
                bcpgIn.ReadFully(salt);
            }

            switch (keyAlgorithm)
            {
            case PublicKeyAlgorithmTag.RsaGeneral:
            case PublicKeyAlgorithmTag.RsaSign:
                MPInteger v = new MPInteger(bcpgIn);
				signature = new MPInteger[1]{ v };
                break;
			case PublicKeyAlgorithmTag.Dsa:
                MPInteger r = new MPInteger(bcpgIn);
                MPInteger s = new MPInteger(bcpgIn);
				signature = new MPInteger[2]{ r, s };
                break;
            case PublicKeyAlgorithmTag.ElGamalEncrypt: // yep, this really does happen sometimes.
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                MPInteger p = new MPInteger(bcpgIn);
                MPInteger g = new MPInteger(bcpgIn);
                MPInteger y = new MPInteger(bcpgIn);
				signature = new MPInteger[3]{ p, g, y };
                break;
            case PublicKeyAlgorithmTag.ECDsa:
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                MPInteger ecR = new MPInteger(bcpgIn);
                MPInteger ecS = new MPInteger(bcpgIn);
                signature = new MPInteger[2]{ ecR, ecS };
                break;

            case PublicKeyAlgorithmTag.Ed25519:
                // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-ed2
                signature = null;
                signatureEncoding = new byte[64];
                bcpgIn.ReadFully(signatureEncoding);
                break;
            case PublicKeyAlgorithmTag.Ed448:
                // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-fields-for-ed4
                signature = null;
                signatureEncoding = new byte[114];
                bcpgIn.ReadFully(signatureEncoding);
                break;

            default:
				if (keyAlgorithm < PublicKeyAlgorithmTag.Experimental_1 || keyAlgorithm > PublicKeyAlgorithmTag.Experimental_11)
                    throw new IOException("unknown signature key algorithm: " + keyAlgorithm);

                signature = null;
                signatureEncoding = Streams.ReadAll(bcpgIn);
				break;
            }
        }

		/**
        * Generate a version 4 signature packet.
        *
        * @param signatureType
        * @param keyAlgorithm
        * @param hashAlgorithm
        * @param hashedData
        * @param unhashedData
        * @param fingerprint
        * @param signature
        */
        public SignaturePacket(
            int						signatureType,
            long					keyId,
            PublicKeyAlgorithmTag	keyAlgorithm,
            HashAlgorithmTag		hashAlgorithm,
            SignatureSubpacket[]	hashedData,
            SignatureSubpacket[]	unhashedData,
            byte[]					fingerprint,
            MPInteger[]				signature)
            : this(Version4, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, signature)
        {
        }

		/**
        * Generate a version 2/3 signature packet.
        *
        * @param signatureType
        * @param keyAlgorithm
        * @param hashAlgorithm
        * @param fingerprint
        * @param signature
        */
        public SignaturePacket(
            int						version,
            int						signatureType,
            long					keyId,
            PublicKeyAlgorithmTag	keyAlgorithm,
            HashAlgorithmTag		hashAlgorithm,
            long					creationTime,
            byte[]					fingerprint,
            MPInteger[]				signature)
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, null, null, fingerprint, signature)
        {
			this.creationTime = creationTime;
        }

		public SignaturePacket(
            int						version,
            int						signatureType,
            long					keyId,
            PublicKeyAlgorithmTag	keyAlgorithm,
            HashAlgorithmTag		hashAlgorithm,
            SignatureSubpacket[]	hashedData,
            SignatureSubpacket[]	unhashedData,
            byte[]					fingerprint,
            MPInteger[]				signature)
            : base(PacketTag.Signature)
        {
            this.version = version;
            this.signatureType = signatureType;
            this.keyId = keyId;
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
            this.hashedData = hashedData;
            this.unhashedData = unhashedData;
            this.fingerprint = fingerprint;
            this.signature = signature;

			if (hashedData != null)
			{
				SetCreationTime();
			}
		}

		public int Version => version;

		public int SignatureType => signatureType;

        /**
        * return the keyId
        * @return the keyId that created the signature.
        */
        public long KeyId => keyId;

        /**
         * Return the signatures fingerprint.
         * @return fingerprint (digest prefix) of the signature
         */
        public byte[] GetFingerprint()
        {
            return Arrays.Clone(fingerprint);
        }

		/**
        * return the signature trailer that must be included with the data
        * to reconstruct the signature
        *
        * @return byte[]
        */
        public byte[] GetSignatureTrailer()
        {
			if (version == Version3)
            {
                long time = creationTime / 1000L;

                byte[] trailer = new byte[5];
				trailer[0] = (byte)signatureType;
                Pack.UInt32_To_BE((uint)time, trailer, 1);
                return trailer;
            }

            MemoryStream sOut = new MemoryStream();

			sOut.WriteByte((byte)Version);
            sOut.WriteByte((byte)SignatureType);
            sOut.WriteByte((byte)KeyAlgorithm);
            sOut.WriteByte((byte)HashAlgorithm);

            // Mark position an reserve two bytes (version4) or four bytes (version6)
            // for length
            long lengthPosition = sOut.Position;
            if (version == Version6)
            {
                sOut.WriteByte(0x00);
                sOut.WriteByte(0x00);
            }
            sOut.WriteByte(0x00);
            sOut.WriteByte(0x00);

            SignatureSubpacket[] hashed = GetHashedSubPackets();
			for (int i = 0; i != hashed.Length; i++)
            {
                hashed[i].Encode(sOut);
            }

            ushort dataLength = Convert.ToUInt16(sOut.Position - lengthPosition - 2);
            if (version == Version6)
            {
                dataLength -= 2;
            }

            uint hDataLength = Convert.ToUInt32(sOut.Position);

			sOut.WriteByte((byte)Version);
            sOut.WriteByte(0xff);
            sOut.WriteByte((byte)(hDataLength >> 24));
            sOut.WriteByte((byte)(hDataLength >> 16));
            sOut.WriteByte((byte)(hDataLength >>  8));
            sOut.WriteByte((byte)(hDataLength      ));

            // Reset position and fill in length
            sOut.Position = lengthPosition;
            if (version == Version6)
            {
                sOut.WriteByte((byte)(dataLength >> 24));
                sOut.WriteByte((byte)(dataLength >> 16));
            }
            sOut.WriteByte((byte)(dataLength >> 8));
            sOut.WriteByte((byte)(dataLength     ));

            return sOut.ToArray();
        }

		public PublicKeyAlgorithmTag KeyAlgorithm => keyAlgorithm;

        public HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        /**
		* return the signature as a set of integers - note this is normalised to be the
        * ASN.1 encoding of what appears in the signature packet.
        */
        public MPInteger[] GetSignature() => signature;

        public byte[] GetSignatureSalt()
        {
            return Arrays.Clone(salt);
        }

		/**
		 * Return the byte encoding of the signature section.
		 * @return uninterpreted signature bytes.
		 */
		public byte[] GetSignatureBytes()
		{
			if (signatureEncoding != null)
				return Arrays.Clone(signatureEncoding);

			MemoryStream bOut = new MemoryStream();

            using (var pOut = new BcpgOutputStream(bOut))
            {
                foreach (MPInteger sigObj in signature)
                {
                    try
                    {
                        pOut.WriteObject(sigObj);
                    }
                    catch (IOException e)
                    {
                        throw new Exception("internal error: " + e);
                    }
                }
            }

            return bOut.ToArray();
		}

		public SignatureSubpacket[] GetHashedSubPackets() => hashedData;

		public SignatureSubpacket[] GetUnhashedSubPackets() => unhashedData;

		/// <summary>Return the creation time in milliseconds since 1 Jan., 1970 UTC.</summary>
        public long CreationTime => creationTime;

		public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte((byte)version);

                if (version == Version3 || version == Version2)
                {
                    byte nextBlockLength = 5;
                    pOut.Write(nextBlockLength, (byte)signatureType);
                    pOut.WriteInt((int)(creationTime / 1000L));
                    pOut.WriteLong(keyId);
                    pOut.Write((byte)keyAlgorithm, (byte)hashAlgorithm);
                }
                else if (version >= Version4 && version <= Version6)
                {
                    pOut.Write((byte)signatureType, (byte)keyAlgorithm, (byte)hashAlgorithm);
                    EncodeLengthAndData(version, pOut, GetEncodedSubpackets(hashedData));
                    EncodeLengthAndData(version, pOut, GetEncodedSubpackets(unhashedData));
                }
                else
                {
                    throw new IOException("unknown version: " + version);
                }

                pOut.Write(fingerprint);

                if (version == Version6)
                {
                    pOut.WriteByte((byte)salt.Length);
                    pOut.Write(salt); 
                }

                if (signature != null)
                {
                    pOut.WriteObjects(signature);
                }
                else
                {
                    pOut.Write(signatureEncoding);
                }
            }

			bcpgOut.WritePacket(PacketTag.Signature, bOut.ToArray());
        }

		private static void EncodeLengthAndData(
            int version,
			BcpgOutputStream	pOut,
			byte[]				data)
		{
            if (version == Version6)
            {
                pOut.WriteInt(data.Length);
            }
            else
            {
                pOut.WriteShort((short)data.Length);
            }
			pOut.Write(data);
		}

		private static byte[] GetEncodedSubpackets(
			SignatureSubpacket[] ps)
		{
			MemoryStream sOut = new MemoryStream();

			foreach (SignatureSubpacket p in ps)
			{
				p.Encode(sOut);
			}

			return sOut.ToArray();
		}

		private void SetCreationTime()
		{
			foreach (SignatureSubpacket p in hashedData)
			{
				if (p is SignatureCreationTime signatureCreationTime)
				{
                    creationTime = DateTimeUtilities.DateTimeToUnixMs(signatureCreationTime.GetTime());
					break;
				}
			}
		}

        public static SignaturePacket FromByteArray(byte[] data)
        {
            BcpgInputStream input = BcpgInputStream.Wrap(new MemoryStream(data));

            return new SignaturePacket(input);
        }
    }
}
