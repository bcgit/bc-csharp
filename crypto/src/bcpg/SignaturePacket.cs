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

        public const int DefaultVersion = Version4;

        private readonly int                    version;
        private readonly int                    signatureType;
        private long                            creationTime;
        private long                            keyId;
        private bool                            keyIdAlreadySet = false;
        private readonly PublicKeyAlgorithmTag  keyAlgorithm;
        private readonly HashAlgorithmTag       hashAlgorithm;
        private readonly MPInteger[]            signature;
        private readonly byte[]                 fingerprint;
        private readonly SignatureSubpacket[]   hashedData;
        private readonly SignatureSubpacket[]   unhashedData;
		private readonly byte[]                 signatureEncoding;

        // fields for v6 signatures
        private readonly byte[] salt;
        private byte[] issuerFingerprint = null;

        private void CheckIssuerSubpacket(SignatureSubpacket p)
        {
            if (p is IssuerFingerprint issuerFingerprintPkt && issuerFingerprint is null)
            {
                issuerFingerprint = issuerFingerprintPkt.GetFingerprint();

                if (issuerFingerprintPkt.KeyVersion == PublicKeyPacket.Version4)
                {
                    keyId = (long)Pack.BE_To_UInt64(issuerFingerprint, issuerFingerprint.Length - 8);
                }
                else
                {
                    // v5 or v6
                    keyId = (long)Pack.BE_To_UInt64(issuerFingerprint);
                }
                keyIdAlreadySet = true;
            }

            else if (p is IssuerKeyId issuerKeyId && !keyIdAlreadySet)
            {
                // https://www.rfc-editor.org/rfc/rfc9580#name-issuer-key-id
                // https://www.rfc-editor.org/rfc/rfc9580#issuer-fingerprint-subpacket
                // V6 signatures MUST NOT include an IssuerKeyId subpacket and SHOULD include an IssuerFingerprint subpacket
                if (version == Version6)
                {
                    throw new IOException("V6 signatures MUST NOT include an IssuerKeyId subpacket");
                }
                keyId = issuerKeyId.KeyId;
                keyIdAlreadySet = true;
            }
        }

        internal SignaturePacket(BcpgInputStream bcpgIn)
            :base(PacketTag.Signature)
        {
            version = bcpgIn.RequireByte();

			if (version == Version2 || version == Version3)
            {
//                int l =
                bcpgIn.RequireByte();

				signatureType = bcpgIn.RequireByte();
                creationTime = (long)StreamUtilities.RequireUInt32BE(bcpgIn) * 1000L;
                keyId = (long)StreamUtilities.RequireUInt64BE(bcpgIn);
				keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();
            }
            else if (version >= Version4 && version <= Version6)
            {
                signatureType = bcpgIn.RequireByte();
                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();

                int hashedLength;

                if (version == Version6)
                {
                    hashedLength = (int)StreamUtilities.RequireUInt32BE(bcpgIn);
                }
                else
                {
                    hashedLength = StreamUtilities.RequireUInt16BE(bcpgIn);
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
                    CheckIssuerSubpacket(p);
                    
                    if (p is SignatureCreationTime sigCreationTime)
                    {
                        creationTime = DateTimeUtilities.DateTimeToUnixMs(sigCreationTime.GetTime());
                    }
                }

                int unhashedLength;

                if (version == Version6)
                {
                    unhashedLength = (int)StreamUtilities.RequireUInt32BE(bcpgIn);
                }
                else
                {
                    unhashedLength = StreamUtilities.RequireUInt16BE(bcpgIn);
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
                    CheckIssuerSubpacket(p);
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
                    // https://www.rfc-editor.org/rfc/rfc9580#name-versions-4-and-6-signature-
                    // The salt size MUST match the value defined for the hash algorithm as specified in Table 23
                    // https://www.rfc-editor.org/rfc/rfc9580#hash-algorithms-registry

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
            case PublicKeyAlgorithmTag.ElGamalEncrypt: // yep, this really does happen sometimes.
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                MPInteger r = new MPInteger(bcpgIn);
                MPInteger s = new MPInteger(bcpgIn);
				signature = new MPInteger[2]{ r, s };
                break;
            case PublicKeyAlgorithmTag.ECDsa:
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                MPInteger ecR = new MPInteger(bcpgIn);
                MPInteger ecS = new MPInteger(bcpgIn);
                signature = new MPInteger[2]{ ecR, ecS };
                break;

            case PublicKeyAlgorithmTag.Ed25519:
                // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-fields-for-ed2
                signature = null;
                signatureEncoding = new byte[64];
                bcpgIn.ReadFully(signatureEncoding);
                break;
            case PublicKeyAlgorithmTag.Ed448:
                // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-fields-for-ed4
                signature = null;
                signatureEncoding = new byte[114];
                bcpgIn.ReadFully(signatureEncoding);
                break;

            // https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
                    signature = null;
                    signatureEncoding = new byte[64+3309];
                    bcpgIn.ReadFully(signatureEncoding);
                    break;

            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                signature = null;
                signatureEncoding = new byte[114+4627];
                bcpgIn.ReadFully(signatureEncoding);
                break;

            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
                signature = null;
                signatureEncoding = new byte[7856];
                bcpgIn.ReadFully(signatureEncoding);
                break;

            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
                signature = null;
                signatureEncoding = new byte[17088];
                bcpgIn.ReadFully(signatureEncoding);
                break;

            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                signature = null;
                signatureEncoding = new byte[29792];
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
            : this(Version4, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, null, null, signature)
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
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, null, null, fingerprint, null, null, signature)
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
            :this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, null, null, signature)
        {
		}

        public SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            byte[] salt,
            byte[] issuerFingerprint,
            byte[] signatureEncoding)
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, salt, issuerFingerprint)
        {
            this.signatureEncoding = Arrays.Clone(signatureEncoding);
        }

        public SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            byte[] salt,
            byte[] issuerFingerprint,
            MPInteger[] signature)
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint, salt, issuerFingerprint)
        {
            this.signature = signature;
        }

        private SignaturePacket(
            int version,
            int signatureType,
            long keyId,
            PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData,
            byte[] fingerprint,
            byte[] salt,
            byte[] issuerFingerprint)
            : base(PacketTag.Signature)
        {
            this.version = version;
            this.signatureType = signatureType;
            this.keyId = keyId;
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
            this.hashedData = hashedData;
            this.unhashedData = unhashedData;
            this.fingerprint = Arrays.Clone(fingerprint);
            this.salt = Arrays.Clone(salt);
            this.issuerFingerprint = Arrays.Clone(issuerFingerprint);

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

        public byte[] GetIssuerFingerprint()
        {
            return Arrays.Clone(issuerFingerprint);
        }

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
            return GetSignatureTrailer(Array.Empty<byte>());
        }

        public byte[] GetSignatureTrailer(byte[] additionalMetadata)
        {
			if (version == Version3)
            {
                long time = creationTime / 1000L;

                byte[] trailer = new byte[5];
				trailer[0] = (byte)signatureType;
                Pack.UInt32_To_BE((uint)time, trailer, 1);
                return trailer;
            }

            using (MemoryStream sOut = new MemoryStream())
            {
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

                // Additional metadata for v5 signatures
                // https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-computing-signatures
                // Only for document signatures (type 0x00 or 0x01) the following three data items are
                // hashed here:
                //   * the one-octet content format,
                //   * the file name as a string (one octet length, followed by the file name)
                //   * a four-octet number that indicates a date,
                // The three data items hashed for document signatures need to mirror the values of the
                // Literal Data packet.
                // For detached and cleartext signatures 6 zero bytes are hashed instead.

                if (version == Version5 && (signatureType == 0x00 || signatureType == 0x01))
                {
                    if (additionalMetadata != null && additionalMetadata.Length > 0)
                    {
                        sOut.Write(additionalMetadata, 0, additionalMetadata.Length);
                    }
                    else
                    {
                        sOut.WriteByte(0x00);
                        sOut.WriteByte(0x00);
                        sOut.WriteByte(0x00);
                        sOut.WriteByte(0x00);
                        sOut.WriteByte(0x00);
                        sOut.WriteByte(0x00);
                    }
                }

                sOut.WriteByte((byte)Version);
                sOut.WriteByte(0xff);

                if (version == Version5)
                {
                    sOut.WriteByte((byte)((ulong)hDataLength >> 56));
                    sOut.WriteByte((byte)((ulong)hDataLength >> 48));
                    sOut.WriteByte((byte)((ulong)hDataLength >> 40));
                    sOut.WriteByte((byte)((ulong)hDataLength >> 32));
                }
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
