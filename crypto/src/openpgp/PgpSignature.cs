using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>A PGP signature object.</remarks>
    public class PgpSignature
    {
        private static SignaturePacket Cast(Packet packet)
        {
			if (packet is SignaturePacket signaturePacket)
				return signaturePacket;

            throw new IOException("unexpected packet in stream: " + packet);
        }

        public const int BinaryDocument = 0x00;
        public const int CanonicalTextDocument = 0x01;
        public const int StandAlone = 0x02;

        public const int DefaultCertification = 0x10;
        public const int NoCertification = 0x11;
        public const int CasualCertification = 0x12;
        public const int PositiveCertification = 0x13;

        public const int SubkeyBinding = 0x18;
		public const int PrimaryKeyBinding = 0x19;
		public const int DirectKey = 0x1f;
        public const int KeyRevocation = 0x20;
        public const int SubkeyRevocation = 0x28;
        public const int CertificationRevocation = 0x30;
        public const int Timestamp = 0x40;
        public const int ThirdPartyConfirmation = 0x50;

        private readonly SignaturePacket	sigPck;
        private readonly int				signatureType;
        private readonly TrustPacket		trustPck;

		private ISigner	sig;
		private byte	lastb; // Initial value anything but '\r'

		internal PgpSignature(
            BcpgInputStream bcpgInput)
            : this(Cast(bcpgInput.ReadPacket()))
        {
        }

		internal PgpSignature(SignaturePacket sigPacket)
			: this(sigPacket, null)
        {
        }

        internal PgpSignature(SignaturePacket sigPacket, TrustPacket trustPacket)
        {
			this.sigPck = sigPacket ?? throw new ArgumentNullException(nameof(sigPacket));
			this.signatureType = sigPck.SignatureType;
			this.trustPck = trustPacket;
        }

		/// <summary>The OpenPGP version number for this signature.</summary>
		public int Version
		{
			get { return sigPck.Version; }
		}

		/// <summary>The key algorithm associated with this signature.</summary>
		public PublicKeyAlgorithmTag KeyAlgorithm
		{
			get { return sigPck.KeyAlgorithm; }
		}

		/// <summary>The hash algorithm associated with this signature.</summary>
		public HashAlgorithmTag HashAlgorithm
		{
			get { return sigPck.HashAlgorithm; }
		}

        /// <summary>Return the digest prefix of the signature.</summary>
        public byte[] GetDigestPrefix()
        {
            return sigPck.GetFingerprint();
        }

        /// <summary>Return true if this signature represents a certification.</summary>
        public bool IsCertification()
        {
            return IsCertification(SignatureType);
        }

		public void InitVerify(PgpPublicKey pubKey)
        {
			lastb = 0;
			AsymmetricKeyParameter key = pubKey.GetKey();

            if (sig == null)
			{
                this.sig = PgpUtilities.CreateSigner(sigPck.KeyAlgorithm, sigPck.HashAlgorithm, key);
            }

            try
            {
                sig.Init(false, key);

                if (Version == SignaturePacket.Version6)
                {
                    byte[] salt = GetSignatureSalt();
                    sig.BlockUpdate(salt, 0, salt.Length);
                }
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }
        }

        public void Update(byte b)
        {
            if (signatureType == CanonicalTextDocument)
            {
				DoCanonicalUpdateByte(b);
            }
            else
            {
                sig.Update(b);
            }
        }

		private void DoCanonicalUpdateByte(byte b)
		{
			if (b == '\r')
			{
				DoUpdateCRLF();
			}
			else if (b == '\n')
			{
				if (lastb != '\r')
				{
					DoUpdateCRLF();
				}
			}
			else
			{
				sig.Update(b);
			}

			lastb = b;
		}

		private void DoUpdateCRLF()
		{
			sig.Update((byte)'\r');
			sig.Update((byte)'\n');
		}

		public void Update(params byte[] bytes)
        {
			Update(bytes, 0, bytes.Length);
        }

		public void Update(byte[] bytes, int off, int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Update(bytes.AsSpan(off, length));
#else
            if (signatureType == CanonicalTextDocument)
            {
                int finish = off + length;

				for (int i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.BlockUpdate(bytes, off, length);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
            if (signatureType == CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                sig.BlockUpdate(input);
            }
        }
#endif

        public bool Verify()
        {
            byte[] trailer = GetSignatureTrailer();

            sig.BlockUpdate(trailer, 0, trailer.Length);

			return sig.VerifySignature(GetSignature());
        }

        public bool Verify(byte[] additionalMetadata)
        {
            // Additional metadata for v5 signatures
            byte[] trailer = sigPck.GetSignatureTrailer(additionalMetadata);

            sig.BlockUpdate(trailer, 0, trailer.Length);

            return sig.VerifySignature(GetSignature());
        }

        private void UpdateWithIdData(int header, byte[] idBytes)
		{
			this.Update(
				(byte) header,
				(byte)(idBytes.Length >> 24),
				(byte)(idBytes.Length >> 16),
				(byte)(idBytes.Length >> 8),
				(byte)(idBytes.Length));
			this.Update(idBytes);
		}

		private void UpdateWithPublicKey(PgpPublicKey key)
		{
			byte[] keyBytes = GetEncodedPublicKey(key);

            this.Update(PgpPublicKey.FingerprintPreamble(Version));

            switch (Version)
            {
                case SignaturePacket.Version4:
                    this.Update(
                        (byte)(keyBytes.Length >> 8),
                        (byte)(keyBytes.Length));
                    break;
                case SignaturePacket.Version5:
                case SignaturePacket.Version6:
                    this.Update(
                        (byte)(keyBytes.Length >> 24),
                        (byte)(keyBytes.Length >> 16),
                        (byte)(keyBytes.Length >> 8),
                        (byte)(keyBytes.Length));
                    break;
            }

			this.Update(keyBytes);
		}

		/// <summary>
		/// Verify the signature as certifying the passed in public key as associated
		/// with the passed in user attributes.
		/// </summary>
		/// <param name="userAttributes">User attributes the key was stored under.</param>
		/// <param name="key">The key to be verified.</param>
		/// <returns>True, if the signature matches, false otherwise.</returns>
		public bool VerifyCertification(PgpUserAttributeSubpacketVector	userAttributes, PgpPublicKey key)
		{
			UpdateWithPublicKey(key);

			//
			// hash in the userAttributes
			//
			try
			{
				var bOut = new MemoryStream();
				foreach (UserAttributeSubpacket packet in userAttributes.ToSubpacketArray())
				{
					packet.Encode(bOut);
				}
				UpdateWithIdData(0xd1, bOut.ToArray());
			}
			catch (IOException e)
			{
				throw new PgpException("cannot encode subpacket array", e);
			}

			return Verify();
		}

		/// <summary>
		/// Verify the signature as certifying the passed in public key as associated
		/// with the passed in ID.
		/// </summary>
		/// <param name="id">ID the key was stored under.</param>
		/// <param name="key">The key to be verified.</param>
		/// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(string id, PgpPublicKey key)
        {
			UpdateWithPublicKey(key);

			//
            // hash in the id
            //
            UpdateWithIdData(0xb4, Strings.ToUtf8ByteArray(id));

            return Verify();
        }

		/// <summary>Verify a certification for the passed in key against the passed in master key.</summary>
		/// <param name="masterKey">The key we are verifying against.</param>
		/// <param name="pubKey">The key we are verifying.</param>
		/// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey	masterKey,
            PgpPublicKey	pubKey)
        {
			UpdateWithPublicKey(masterKey);
			UpdateWithPublicKey(pubKey);

			return Verify();
        }

		/// <summary>Verify a key certification, such as revocation, for the passed in key.</summary>
		/// <param name="pubKey">The key we are checking.</param>
		/// <returns>True, if the certification is valid, false otherwise.</returns>
        public bool VerifyCertification(
            PgpPublicKey pubKey)
        {
            if (SignatureType != KeyRevocation
                && SignatureType != SubkeyRevocation
                && SignatureType != DirectKey)
            {
                throw new InvalidOperationException("signature is not a key signature");
            }

			UpdateWithPublicKey(pubKey);

			return Verify();
        }

		public int SignatureType
        {
			get { return sigPck.SignatureType; }
        }

		/// <summary>The ID of the key that created the signature.</summary>
        public long KeyId
        {
            get { return sigPck.KeyId; }
        }

        public byte[] GetIssuerFingerprint()
        {
            return sigPck.GetIssuerFingerprint();
        }

        /// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime
        {
			get { return DateTimeUtilities.UnixMsToDateTime(sigPck.CreationTime); }
        }

		public byte[] GetSignatureTrailer()
        {
            return sigPck.GetSignatureTrailer();
        }

        public byte[] GetSignatureTrailer(byte[] additionalMetadata)
        {
            // Additional metadata for v5 signatures
            return sigPck.GetSignatureTrailer(additionalMetadata);
        }

        public byte[] GetSignatureSalt()
        {
            return sigPck.GetSignatureSalt();
        }

        /// <summary>
        /// Return true if the signature has either hashed or unhashed subpackets.
        /// </summary>
        public bool HasSubpackets
		{
			get
			{
				return sigPck.GetHashedSubPackets() != null
					|| sigPck.GetUnhashedSubPackets() != null;
			}
		}

		public PgpSignatureSubpacketVector GetHashedSubPackets()
        {
            return CreateSubpacketVector(sigPck.GetHashedSubPackets());
        }

		public PgpSignatureSubpacketVector GetUnhashedSubPackets()
        {
            return CreateSubpacketVector(sigPck.GetUnhashedSubPackets());
        }

		private static PgpSignatureSubpacketVector CreateSubpacketVector(SignatureSubpacket[] pcks)
		{
			return pcks == null ? null : new PgpSignatureSubpacketVector(pcks);
		}

		public byte[] GetSignature()
        {
            MPInteger[] sigValues = sigPck.GetSignature();
            byte[] signature;

			if (sigValues != null)
			{
				if (sigValues.Length == 1)    // an RSA signature
				{
					signature = sigValues[0].Value.ToByteArrayUnsigned();
				}
                else if (KeyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
                {
					if (sigValues.Length != 2)
						throw new InvalidOperationException();

					BigInteger v0 = sigValues[0].Value;
                    BigInteger v1 = sigValues[1].Value;

					if (v0.BitLength == 918 &&
                        v1.Equals(BigInteger.Zero) &&
						v0.ShiftRight(912).Equals(BigInteger.ValueOf(0x40)))
					{
						signature = new byte[Ed448.SignatureSize];
						BigIntegers.AsUnsignedByteArray(v0.ClearBit(918), signature, 0, signature.Length);
					}
					else if (v0.BitLength <= 256 && v1.BitLength <= 256)
					{
                        signature = new byte[Ed25519.SignatureSize];
                        BigIntegers.AsUnsignedByteArray(sigValues[0].Value, signature,  0, 32);
                        BigIntegers.AsUnsignedByteArray(sigValues[1].Value, signature, 32, 32);
                    }
                    else
					{
                        throw new InvalidOperationException();
                    }
                }
                else
                {
                    if (sigValues.Length != 2)
                        throw new InvalidOperationException();

                    try
                    {
						signature = new DerSequence(
							new DerInteger(sigValues[0].Value),
							new DerInteger(sigValues[1].Value)).GetEncoded();
					}
					catch (IOException e)
					{
						throw new PgpException("exception encoding DSA sig.", e);
					}
				}
			}
			else
			{
				signature = sigPck.GetSignatureBytes();
			}

			return signature;
        }

		// TODO Handle the encoding stuff by subclassing BcpgObject?
		public byte[] GetEncoded()
        {
            var bOut = new MemoryStream();

			Encode(bOut);

			return bOut.ToArray();
        }

        public void Encode(Stream outStream)
        {
            Encode(outStream, false);
        }

        /**
         * Encode the signature to outStream, with trust packets stripped out if forTransfer is true.
         *
         * @param outStream   stream to write the key encoding to.
         * @param forTransfer if the purpose of encoding is to send key to other users.
         * @throws IOException in case of encoding error.
         */
        public void Encode(Stream outStream, bool forTransfer)
        {
            // Exportable signatures MUST NOT be exported if forTransfer==true
            if (forTransfer && (!GetHashedSubPackets().IsExportable() || !GetUnhashedSubPackets().IsExportable()))
                return;

            var bcpgOut = BcpgOutputStream.Wrap(outStream);

            bcpgOut.WritePacket(sigPck);
            if (!forTransfer && trustPck != null)
            {
                bcpgOut.WritePacket(trustPck);
            }
        }

		private static byte[] GetEncodedPublicKey(PgpPublicKey pubKey) 
		{
			try
			{
				return pubKey.publicPk.GetEncodedContents();
			}
			catch (IOException e)
			{
				throw new PgpException("exception preparing key.", e);
			}
		}

        /// <summary>
        /// Return true if the passed in signature type represents a certification, false if the signature type is not.
        /// </summary>
        /// <param name="signatureType"></param>
        /// <returns>true if signatureType is a certification, false otherwise.</returns>
        public static bool IsCertification(int signatureType)
        {
            switch (signatureType)
            {
            case DefaultCertification:
            case NoCertification:
            case CasualCertification:
            case PositiveCertification:
                return true;
            default:
                return false;
            }
        }

        public static bool IsSignatureEncodingEqual(PgpSignature sig1, PgpSignature sig2)
        {
            return Arrays.AreEqual(sig1.sigPck.GetSignatureBytes(), sig2.sigPck.GetSignatureBytes());
        }

        public static PgpSignature Join(PgpSignature sig1, PgpSignature sig2)
        {
            if (!IsSignatureEncodingEqual(sig1, sig2))
                throw new ArgumentException("These are different signatures.");

            // merge unhashed subpackets
            SignatureSubpacket[] sig1Unhashed = sig1.GetUnhashedSubPackets().ToSubpacketArray();
            SignatureSubpacket[] sig2Unhashed = sig2.GetUnhashedSubPackets().ToSubpacketArray();

            var merged = new List<SignatureSubpacket>(sig1Unhashed);

            foreach (var subpacket in sig2Unhashed)
            {
                if (!merged.Contains(subpacket))
                {
                    merged.Add(subpacket);
                }
            }

            SignatureSubpacket[] unhashed = merged.ToArray();

            SignaturePacket sigpkt;

            if (
                sig1.KeyAlgorithm == PublicKeyAlgorithmTag.Ed25519
                || sig1.KeyAlgorithm == PublicKeyAlgorithmTag.Ed448
                || sig1.KeyAlgorithm == PublicKeyAlgorithmTag.MLDsa65_Ed25519
                || sig1.KeyAlgorithm == PublicKeyAlgorithmTag.MLDsa87_Ed448
                || sig1.KeyAlgorithm == PublicKeyAlgorithmTag.SlhDsa_Shake128s
                || sig1.KeyAlgorithm == PublicKeyAlgorithmTag.SlhDsa_Shake128f
                || sig1.KeyAlgorithm == PublicKeyAlgorithmTag.SlhDsa_Shake256s)
            {
                sigpkt = new SignaturePacket(
                    sig1.Version,
                    sig1.SignatureType,
                    sig1.KeyId,
                    sig1.KeyAlgorithm,
                    sig1.HashAlgorithm,
                    sig1.GetHashedSubPackets().ToSubpacketArray(),
                    unhashed,
                    sig1.GetDigestPrefix(),
                    sig1.GetSignatureSalt(),
                    sig1.GetIssuerFingerprint(),
                    sig1.sigPck.GetSignatureBytes());
            }
            else
            {
                sigpkt = new SignaturePacket(
                    sig1.Version,
                    sig1.SignatureType,
                    sig1.KeyId,
                    sig1.KeyAlgorithm,
                    sig1.HashAlgorithm,
                    sig1.GetHashedSubPackets().ToSubpacketArray(),
                    unhashed,
                    sig1.GetDigestPrefix(),
                    sig1.GetSignatureSalt(),
                    sig1.GetIssuerFingerprint(),
                    sig1.sigPck.GetSignature());
            }


            return new PgpSignature(sigpkt);
        }
    }
}
