using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
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

		// RFC 9580 5.2.3: a version 6 signature carries the first two octets of its digest. If the signer does not
		// provide the digest, it is computed in parallel.
		private IDigest m_prefixDigest;

		// Set by InitVerify if the signature cannot be valid for the key, for example because of its version
		private bool m_unusable;

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
			m_prefixDigest = null;

			// Signatures that cannot be valid for this key are rejected by Verify, without touching the signer
			m_unusable = !IsUsableWith(pubKey);
			if (m_unusable)
				return;

			AsymmetricKeyParameter key = pubKey.GetKey();

            // RFC 9580 5.2.3.3: an EdDSALegacy key over Ed448 needs a larger digest than its algorithm alone says
            if (!PgpUtilities.IsHashStrongEnough(KeyAlgorithm, HashAlgorithm, key))
            {
                m_unusable = true;
                return;
            }

            if (sig == null)
			{
                this.sig = PgpUtilities.CreateSigner(sigPck.KeyAlgorithm, sigPck.HashAlgorithm, key);
            }

            try
            {
                sig.Init(false, key);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("invalid key.", e);
            }

			if (sigPck.Version == SignaturePacket.Version6)
			{
				// RFC 9580 5.2.4: the salt is hashed before the data
				byte[] salt = sigPck.GetSalt();
				sig.BlockUpdate(salt, 0, salt.Length);

				if (!(sig is PgpDigestSigner))
				{
					m_prefixDigest = PgpUtilities.CreateDigest(sigPck.HashAlgorithm);
					m_prefixDigest.BlockUpdate(salt, 0, salt.Length);
				}
			}
        }

		/// <summary>
		/// The signature cannot be valid: its value could not be interpreted, its type is the reserved one or its hash is
		/// MD5 or MD2, or it is a version 6 signature without a hashed creation time, of an unknown type or with an
		/// unknown critical hashed subpacket (RFC 9580 5.2.3.7, 5.2.3.11, 5.2.5).
		/// </summary>
		internal bool IsUnusable => sigPck.IsMalformed || sigPck.SignatureType == 0xFF ||
			// RFC 9580 5.2.5: a hash known to be weak, as MD5 (and MD2, weaker still), is never validated
			sigPck.HashAlgorithm == HashAlgorithmTag.MD5 || sigPck.HashAlgorithm == HashAlgorithmTag.MD2 ||
			(sigPck.Version == SignaturePacket.Version6 && IsMalformedVersion6Signature());

		// TODO[api] Apply these rules to version 4 signatures too
		private bool IsMalformedVersion6Signature()
		{
			if (!IsKnownSignatureType(sigPck.SignatureType))
				return true;

			// RFC 9580 5.2.5: a subpacket shorter than its length says, which the parser took at its fixed length
			if (sigPck.HasRepairedSubpackets)
				return true;

			bool hasCreationTime = false;
			foreach (SignatureSubpacket subpacket in sigPck.GetHashedSubPackets() ?? new SignatureSubpacket[0])
			{
				if (subpacket.SubpacketType == SignatureSubpacketTag.CreationTime)
				{
					hasCreationTime = true;
				}
				// RFC 9580 5.2.3.12: the signer of a version 6 signature does not include an issuer key ID (one in the
				// unhashed area, which anyone can add, is tolerated)
				else if (subpacket.SubpacketType == SignatureSubpacketTag.IssuerKeyId)
				{
					return true;
				}
				else if (subpacket.IsCritical() &&
					!Enum.IsDefined(typeof(SignatureSubpacketTag), subpacket.SubpacketType))
				{
					return true;
				}
				// RFC 9580 5.2.3.24: criticality applies to the specific notation, and no notation has a meaning
				// here, so a critical one is unknown
				else if (subpacket.IsCritical() && subpacket.SubpacketType == SignatureSubpacketTag.NotationData)
				{
					return true;
				}

				if (!HasExpectedLength(subpacket))
					return true;
			}
			foreach (SignatureSubpacket subpacket in sigPck.GetUnhashedSubPackets() ?? new SignatureSubpacket[0])
			{
				if (!HasExpectedLength(subpacket))
					return true;
			}

			return !hasCreationTime;
		}

		/// <summary>
		/// Whether a known subpacket has the length that its type gives (RFC 9580 5.2.5: a subpacket with a length
		/// that diverges from the expected length makes the signature malformed).
		/// </summary>
		private static bool HasDigestSize(HashAlgorithmTag hashAlgorithm, int length)
		{
			try
			{
				return PgpUtilities.CreateDigest(hashAlgorithm).GetDigestSize() == length;
			}
			catch (Exception e) when (e is PgpException || e is SecurityUtilityException)
			{
				// an unknown hash algorithm
				return true;
			}
		}

		private static bool HasExpectedLength(SignatureSubpacket subpacket)
		{
			byte[] data = subpacket.Data;
			switch (subpacket.SubpacketType)
			{
			case SignatureSubpacketTag.CreationTime:
			case SignatureSubpacketTag.ExpireTime:
			case SignatureSubpacketTag.KeyExpireTime:
				return data.Length == 4;
			case SignatureSubpacketTag.Exportable:
			case SignatureSubpacketTag.Revocable:
			case SignatureSubpacketTag.PrimaryUserId:
				return data.Length == 1;
			case SignatureSubpacketTag.TrustSig:
				return data.Length == 2;
			case SignatureSubpacketTag.IssuerKeyId:
				return data.Length == 8;
			case SignatureSubpacketTag.RevocationKey:
				return data.Length == 22;
			case SignatureSubpacketTag.RevocationReason:
				return data.Length >= 1;
			case SignatureSubpacketTag.IssuerFingerprint:
			case SignatureSubpacketTag.IntendedRecipientFingerprint:
				// a version octet and a fingerprint of the length of that version, where it is known
				return data.Length >= 1 && (data[0] == 4 ? data.Length == 21 : data[0] != 6 || data.Length == 33);
			case SignatureSubpacketTag.PreferredAeadAlgorithms:
				// pairs of a symmetric and an AEAD algorithm
				return data.Length % 2 == 0;
			case SignatureSubpacketTag.SignatureTarget:
				// a public key algorithm, a hash algorithm and a digest of its size, where it is known
				return data.Length >= 2 && HasDigestSize((HashAlgorithmTag)data[1], data.Length - 2);
			case SignatureSubpacketTag.NotationData:
			{
				// flags, the two lengths, and the name and the value of those lengths
				int header = NotationData.HeaderFlagLength + NotationData.HeaderNameLength +
					NotationData.HeaderValueLength;
				return data.Length >= header && data.Length == header + Pack.BE_To_UInt16(data, 4) +
					Pack.BE_To_UInt16(data, 6);
			}
			default:
				return true;
			}
		}

		internal static bool IsKnownSignatureType(int signatureType)
		{
			switch (signatureType)
			{
			case BinaryDocument:
			case CanonicalTextDocument:
			case StandAlone:
			case DefaultCertification:
			case NoCertification:
			case CasualCertification:
			case PositiveCertification:
			case SubkeyBinding:
			case PrimaryKeyBinding:
			case DirectKey:
			case KeyRevocation:
			case SubkeyRevocation:
			case CertificationRevocation:
			case Timestamp:
			case ThirdPartyConfirmation:
				return true;
			default:
				return false;
			}
		}

		/// <summary>An Issuer Fingerprint subpacket has a key version that differs from the signature version.</summary>
		internal bool HasIssuerFingerprintVersionMismatch => sigPck.IssuerFingerprintVersionMismatch;

		/// <summary>Whether the signature can be valid for the key (RFC 9580 5.2.3, 5.2.1.16).</summary>
		private bool IsUsableWith(PgpPublicKey pubKey)
		{
			// malformed signatures and the reserved signature type 0xFF MUST NOT be validated
			if (IsUnusable)
				return false;

			// the key has to be of the algorithm of the signature (the two kinds of RSA key sign alike)
			if (!PgpUtilities.IsSignatureAlgorithmCompatible(sigPck.KeyAlgorithm, pubKey.Algorithm))
				return false;

			// RFC 9580 10.3.2.2: a version 6 key makes version 6 signatures and the other way around
			bool isV6Key = pubKey.Version == PublicKeyPacket.Version6;
			bool isV6Signature = sigPck.Version == SignaturePacket.Version6;
			if (isV6Key != isV6Signature)
				return false;

			// RFC 9580 5.2.3.35: an issuer fingerprint names a key of the version of the signature
			if (sigPck.IssuerFingerprintVersionMismatch)
				return false;

			if (isV6Signature)
			{
				byte[] salt = sigPck.GetSalt();
				if (salt == null || salt.Length != PgpUtilities.GetV6SaltSize(sigPck.HashAlgorithm))
					return false;
			}

			return true;
		}

		private void DoUpdateSigner(byte b)
		{
			sig.Update(b);
			m_prefixDigest?.Update(b);
		}

		private void DoUpdateSigner(byte[] bytes, int off, int length)
		{
			sig.BlockUpdate(bytes, off, length);
			m_prefixDigest?.BlockUpdate(bytes, off, length);
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		private void DoUpdateSigner(ReadOnlySpan<byte> input)
		{
			sig.BlockUpdate(input);
			m_prefixDigest?.BlockUpdate(input);
		}
#endif

        public void Update(byte b)
        {
			if (m_unusable)
				return;

            if (signatureType == CanonicalTextDocument)
            {
				DoCanonicalUpdateByte(b);
            }
            else
            {
                DoUpdateSigner(b);
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
				DoUpdateSigner(b);
			}

			lastb = b;
		}

		private void DoUpdateCRLF()
		{
			DoUpdateSigner((byte)'\r');
			DoUpdateSigner((byte)'\n');
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
			if (m_unusable)
				return;

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
                DoUpdateSigner(bytes, off, length);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
			if (m_unusable)
				return;

            if (signatureType == CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                DoUpdateSigner(input);
            }
        }
#endif

        public bool Verify()
        {
			if (m_unusable)
				return false;

            if (!PgpUtilities.IsHashStrongEnough(KeyAlgorithm, HashAlgorithm))
                return false;

            byte[] trailer = GetSignatureTrailer();

            DoUpdateSigner(trailer, 0, trailer.Length);

			if (!sig.VerifySignature(GetSignature()))
				return false;

			// RFC 9580 5.2.3: a version 6 signature must carry the first two octets of its digest
			return sigPck.Version != SignaturePacket.Version6 || DigestPrefixMatches();
        }

		private bool DigestPrefixMatches()
		{
			byte[] digest = m_prefixDigest != null
				? DigestUtilities.DoFinal(m_prefixDigest)
				: (sig as PgpDigestSigner)?.LastDigest;

			byte[] prefix = sigPck.GetFingerprint();

			return digest != null && digest.Length >= 2 && prefix.Length == 2
				&& digest[0] == prefix[0] && digest[1] == prefix[1];
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

			if (sigPck.Version == SignaturePacket.Version6)
			{
				// RFC 9580 5.2.4: 0x9B and a 4-octet length for version 6 signatures
				this.Update(
					(byte)0x9B,
					(byte)(keyBytes.Length >> 24),
					(byte)(keyBytes.Length >> 16),
					(byte)(keyBytes.Length >> 8),
					(byte)(keyBytes.Length));
			}
			else
			{
				this.Update(
					(byte)0x99,
					(byte)(keyBytes.Length >> 8),
					(byte)(keyBytes.Length));
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

        /// <summary>
        /// Verify the signature as certifying the passed in public key as associated with the passed in ID, given in
        /// raw byte form.
        /// </summary>
        /// <remarks>
        /// The strings of <see cref="PgpPublicKey.GetUserIds"/> are not decoded as UTF-8, so a user ID with other
        /// than ASCII characters is best verified in the raw form of <see cref="PgpPublicKey.GetRawUserIds"/>.
        /// </remarks>
        /// <param name="rawId">ID the key was stored under, in raw byte form.</param>
        /// <param name="key">The key to be verified.</param>
        /// <returns>True, if the signature matches, false otherwise.</returns>
        public bool VerifyCertification(byte[] rawId, PgpPublicKey key)
        {
            if (rawId == null)
                throw new ArgumentNullException(nameof(rawId));

            UpdateWithPublicKey(key);
            UpdateWithIdData(0xb4, rawId);

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
            // RFC 9580 10.1.1, 10.1.3: a subkey of another version than its primary key is not bound to it
            if ((SignatureType == SubkeyBinding || SignatureType == PrimaryKeyBinding) &&
                masterKey.Version != pubKey.Version)
            {
                return false;
            }

            // RFC 9980 7.2: subkey bindings over keys of the RFC 9980 algorithms made with weak hashes are invalid
            if (SignatureType == SubkeyBinding && PgpUtilities.IsRfc9980Algorithm(pubKey.Algorithm) &&
                PgpUtilities.IsWeakBindingHash(HashAlgorithm))
            {
                return false;
            }

			UpdateWithPublicKey(masterKey);
			UpdateWithPublicKey(pubKey);

			return Verify();
        }

		/// <summary>
		/// Verify a key certification, such as a revocation or a direct-key signature, for the passed in key.
		/// </summary>
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

        /// <summary>The Key ID of the key that created the signature.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => sigPck.KeyId;

		/// <summary>The creation time of this signature.</summary>
        public DateTime CreationTime
        {
			get { return DateTimeUtilities.UnixMsToDateTime(sigPck.CreationTime); }
        }

		public byte[] GetSignatureTrailer()
        {
            return sigPck.GetSignatureTrailer();
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

        /// <summary>The octets of the signature packet without its header.</summary>
        internal byte[] GetEncodedPacketBody() => sigPck.GetEncodedBody();

        /// <summary>Return the salt of a version 6 signature.</summary>
        /// <returns>A copy of the salt, or null if the signature is not of version 6.</returns>
        public byte[] GetSalt() => sigPck.GetSalt();

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
                        BigIntegers.AsUnsignedByteArray(sigValues[0].Value, signature, 0, 32);
                        BigIntegers.AsUnsignedByteArray(sigValues[1].Value, signature, 32, 32);
                    }
                    else
                    {
                        throw new PgpException("Malformed EdDsa legacy signature encoding (too long).");
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
            if (forTransfer && (IsNotExportable(GetHashedSubPackets()) || IsNotExportable(GetUnhashedSubPackets())))
                return;

            var bcpgOut = BcpgOutputStream.Wrap(outStream);

            sigPck.Encode(bcpgOut);

            if (!forTransfer)
            {
                trustPck?.Encode(bcpgOut);
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

        private static bool IsNotExportable(PgpSignatureSubpacketVector subPackets) =>
            subPackets != null && !subPackets.IsExportable();

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

            // The copy keeps version, packet format and the signature value, including raw (non-MPI) encodings.
            return new PgpSignature(sig1.sigPck.WithUnhashedSubpackets(unhashed));
        }
    }
}
