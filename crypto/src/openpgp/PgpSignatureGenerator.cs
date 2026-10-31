using System;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Generator for PGP signatures.</remarks>
    public class PgpSignatureGenerator
    {
		private static readonly SignatureSubpacket[] EmptySignatureSubpackets = new SignatureSubpacket[0];

		private readonly PublicKeyAlgorithmTag keyAlgorithm;
        private readonly HashAlgorithmTag hashAlgorithm;

        private PgpPrivateKey			privKey;
        private int						m_version = 4;
        private byte[]					m_salt;
        private bool					m_generated;
        private ISigner					sig;
        private IDigest					dig;
        private int						signatureType;
        private byte					lastb;

		private SignatureSubpacket[] unhashed = EmptySignatureSubpackets;
        private SignatureSubpacket[] hashed = EmptySignatureSubpackets;

		/// <summary>Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.</summary>
        public PgpSignatureGenerator(
            PublicKeyAlgorithmTag	keyAlgorithm,
            HashAlgorithmTag		hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;

			dig = PgpUtilities.CreateDigest(hashAlgorithm);
        }

		/// <summary>Initialise the generator for signing.</summary>
        public void InitSign(int sigType, PgpPrivateKey privKey)
        {
			InitSign(sigType, privKey, null);
        }

		/// <summary>Initialise the generator for signing.</summary>
		public void InitSign(int sigType, PgpPrivateKey privKey, SecureRandom random)
		{
			// RFC 9580 5.2.1.16: the reserved signature type must not be created
			if (sigType == 0xFF)
				throw new ArgumentException("the signature type 0xFF is reserved", nameof(sigType));

			// RFC 9580 10.3.2.2: version 6 keys make version 6 signatures, other keys version 4 signatures
			int version = privKey.PublicKeyPacket.Version == PublicKeyPacket.Version6 ? 6 : 4;
			if (version == 6)
			{
				// RFC 9580 5.2.5: a version 6 signature of an unknown type does not validate
				if (!PgpSignature.IsKnownSignatureType(sigType))
					throw new ArgumentException("unknown signature type: " + sigType, nameof(sigType));

				if (PgpUtilities.GetV6SaltSize(hashAlgorithm) < 0)
					throw new PgpException("hash algorithm cannot be used for version 6 signatures: " + hashAlgorithm);
				if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
					throw new PgpException("EdDSALegacy cannot be used for version 6 signatures");
			}
			else if (IsVersion6OnlyAlgorithm(keyAlgorithm))
			{
				throw new PgpException(keyAlgorithm + " signatures require a version 6 key");
			}

			// the signature is of the algorithm of the key: EdDSALegacy and Ed25519 are distinct algorithms, for example
			if (!PgpUtilities.IsSignatureAlgorithmCompatible(keyAlgorithm, privKey.PublicKeyPacket.Algorithm))
				throw new PgpException("signature algorithm " + keyAlgorithm + " does not match the key algorithm "
					+ privKey.PublicKeyPacket.Algorithm);

			// RFC 9580 9.5: no new signatures with MD5, SHA-1 or RIPEMD-160; existing ones still verify
			if (PgpUtilities.IsWeakBindingHash(hashAlgorithm))
				throw new PgpException("hash algorithm not allowed for new signatures: " + hashAlgorithm);

			if (!PgpUtilities.IsHashStrongEnough(keyAlgorithm, hashAlgorithm, privKey.Key))
				throw new PgpException("hash algorithm too weak for " + keyAlgorithm + " signatures: " + hashAlgorithm);

			if (random == null)
			{
				random = CryptoServicesRegistrar.GetSecureRandom();
			}

			this.privKey = privKey;
			this.signatureType = sigType;
			m_version = version;
			m_salt = null;
			m_generated = false;

			AsymmetricKeyParameter key = privKey.Key;

            this.sig = PgpUtilities.CreateSigner(keyAlgorithm, hashAlgorithm, key);

            try
			{
				ICipherParameters cp = key;

				// TODO Ask SignerUtilities whether random is permitted?
				if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
				{
					// EdDSA signers don't expect a SecureRandom
				}
				else
				{
					// The signer for Ed25519 and Ed448 keys drops the SecureRandom itself
                    cp = ParameterUtilities.WithRandom(cp, random);
                }

				sig.Init(true, cp);
			}
			catch (InvalidKeyException e)
			{
				throw new PgpException("invalid key.", e);
			}

			dig.Reset();
			lastb = 0;

			if (m_version == 6)
			{
				// RFC 9580 5.2.4: a fresh random salt is hashed before the data
				m_salt = new byte[PgpUtilities.GetV6SaltSize(hashAlgorithm)];
				random.NextBytes(m_salt);

				sig.BlockUpdate(m_salt, 0, m_salt.Length);
				dig.BlockUpdate(m_salt, 0, m_salt.Length);
			}
		}

		private static bool IsVersion6OnlyAlgorithm(PublicKeyAlgorithmTag algorithm)
		{
			switch (algorithm)
			{
			case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
			case PublicKeyAlgorithmTag.MLDsa87_Ed448:
			case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
			case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
			case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
				return true;
			default:
				return false;
			}
		}

		/// <summary>A version 6 signature uses its salt once: the generator has to be initialised again.</summary>
		private void CheckNotGenerated()
		{
			if (m_generated)
				throw new InvalidOperationException("a signature has been generated; call InitSign again");
		}

		public void Update(byte b)
        {
			CheckNotGenerated();

            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
				DoCanonicalUpdateByte(b);
            }
            else
            {
				DoUpdateByte(b);
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
				DoUpdateByte(b);
			}

			lastb = b;
		}

		private void DoUpdateCRLF()
		{
			DoUpdateByte((byte)'\r');
			DoUpdateByte((byte)'\n');
		}

		private void DoUpdateByte(byte b)
		{
			sig.Update(b);
			dig.Update(b);
		}

		public void Update(params byte[] b)
        {
			Update(b, 0, b.Length);
        }

		public void Update(byte[] b, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Update(b.AsSpan(off, len));
#else
			CheckNotGenerated();

            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + len;

				for (int i = off; i != finish; i++)
                {
                    DoCanonicalUpdateByte(b[i]);
                }
            }
            else
            {
                sig.BlockUpdate(b, off, len);
                dig.BlockUpdate(b, off, len);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Update(ReadOnlySpan<byte> input)
        {
			CheckNotGenerated();

            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    DoCanonicalUpdateByte(input[i]);
                }
            }
            else
            {
                sig.BlockUpdate(input);
                dig.BlockUpdate(input);
            }
        }
#endif

        public void SetHashedSubpackets(
            PgpSignatureSubpacketVector hashedPackets)
        {
			hashed = hashedPackets == null
				?	EmptySignatureSubpackets
				:	hashedPackets.ToSubpacketArray();
        }

		public void SetUnhashedSubpackets(
            PgpSignatureSubpacketVector unhashedPackets)
        {
			unhashed = unhashedPackets == null
				?	EmptySignatureSubpackets
				:	unhashedPackets.ToSubpacketArray();
        }

		/// <summary>Return the one pass header associated with the current signature.</summary>
        public PgpOnePassSignature GenerateOnePassVersion(
            bool isNested)
        {
			if (m_version == 6)
			{
				// RFC 9580 5.4: the one-pass signature announces the salt and the fingerprint of the signing key
				byte[] fingerprint = PgpPublicKey.CalculateFingerprint(privKey.PublicKeyPacket);

				return new PgpOnePassSignature(new OnePassSignaturePacket(signatureType, hashAlgorithm, keyAlgorithm,
					m_salt, fingerprint, isNested));
			}

            return new PgpOnePassSignature(
				new OnePassSignaturePacket(
					signatureType, hashAlgorithm, keyAlgorithm, privKey.KeyId, isNested));
        }

		/// <summary>Return a signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
			SignatureSubpacket[] hPkts = hashed, unhPkts = unhashed;

			if (!IsPacketPresent(hashed, SignatureSubpacketTag.CreationTime))
			{
				hPkts = InsertSubpacket(hPkts, new SignatureCreationTime(false, DateTime.UtcNow));
			}

			if (m_version == 6)
			{
				CheckNotGenerated();

				// RFC 9580 5.2.3.12: the issuer key ID must not be in a signature by a key of version 6
				if (IsPacketPresent(hashed, SignatureSubpacketTag.IssuerKeyId)
					|| IsPacketPresent(unhashed, SignatureSubpacketTag.IssuerKeyId))
				{
					throw new PgpException("an issuer key ID is not allowed in version 6 signatures");
				}

				// RFC 9580 5.2.3.23: the revocation key subpacket is deprecated and must not be generated
				// TODO[api] Refuse it in version 4 signatures as well
				if (IsPacketPresent(hashed, SignatureSubpacketTag.RevocationKey)
					|| IsPacketPresent(unhashed, SignatureSubpacketTag.RevocationKey))
				{
					throw new PgpException("a revocation key is not allowed in version 6 signatures");
				}

				// RFC 9580 5.2.3.35: an issuer fingerprint names a key of the version of the signature
				// TODO[api] Refuse one of another version in version 4 signatures as well
				if (HasIssuerFingerprintOfOtherVersion(hashed) || HasIssuerFingerprintOfOtherVersion(unhashed))
					throw new PgpException("an issuer fingerprint of another version is not allowed");

				// RFC 9580 5.2.3.19: the subpacket of a non-exportable signature is critical (SetExportable makes it so)
				// TODO[api] Refuse a non-critical one in version 4 signatures as well
				if (HasNonCriticalNonExportable(hashed) || HasNonCriticalNonExportable(unhashed))
					throw new PgpException("the exportable subpacket of a non-exportable signature must be critical");

				// RFC 9580 5.2.3.35: version 6 signatures identify the issuer by fingerprint, not by key ID
				if (!IsPacketPresent(hashed, SignatureSubpacketTag.IssuerFingerprint)
					&& !IsPacketPresent(unhashed, SignatureSubpacketTag.IssuerFingerprint))
				{
					hPkts = InsertSubpacket(hPkts, new IssuerFingerprint(false, PublicKeyPacket.Version6,
						PgpPublicKey.CalculateFingerprint(privKey.PublicKeyPacket)));
				}
			}
			else if (!IsPacketPresent(hashed, SignatureSubpacketTag.IssuerKeyId)
				&& !IsPacketPresent(unhashed, SignatureSubpacketTag.IssuerKeyId))
			{
				unhPkts = InsertSubpacket(unhPkts, new IssuerKeyId(false, privKey.KeyId));
			}

			int version = m_version;
			byte[] hData;

			try
            {
				MemoryStream hOut = new MemoryStream();

				for (int i = 0; i != hPkts.Length; i++)
				{
					hPkts[i].Encode(hOut);
				}

				byte[] data = hOut.ToArray();

				MemoryStream sOut = new MemoryStream(data.Length + 8);
				sOut.WriteByte((byte)version);
                sOut.WriteByte((byte)signatureType);
                sOut.WriteByte((byte)keyAlgorithm);
                sOut.WriteByte((byte)hashAlgorithm);
				if (version == 6)
				{
					// RFC 9580 5.2.3: 4-octet length of the hashed subpacket area
					sOut.WriteByte((byte)(data.Length >> 24));
					sOut.WriteByte((byte)(data.Length >> 16));
				}
				sOut.WriteByte((byte)(data.Length >> 8));
                sOut.WriteByte((byte)data.Length);
                sOut.Write(data, 0, data.Length);

				hData = sOut.ToArray();
			}
            catch (IOException e)
            {
                throw new PgpException("exception encoding hashed data.", e);
            }

			sig.BlockUpdate(hData, 0, hData.Length);
            dig.BlockUpdate(hData, 0, hData.Length);

			hData = new byte[]
			{
				(byte) version,
				0xff,
				(byte)(hData.Length >> 24),
				(byte)(hData.Length >> 16),
				(byte)(hData.Length >> 8),
				(byte) hData.Length
			};

			sig.BlockUpdate(hData, 0, hData.Length);
            dig.BlockUpdate(hData, 0, hData.Length);

			byte[] sigBytes = sig.GenerateSignature();
			byte[] digest = DigestUtilities.DoFinal(dig);
			byte[] fingerPrint = new byte[2]{ digest[0], digest[1] };

			MPInteger[] sigValues;
			if (IsRawSignatureAlgorithm(keyAlgorithm))
			{
				// RFC 9580 5.2.3.4 and 5.2.3.5, RFC 9980 5.3.1, 6.2.1: the native signature, not MPIs
				PgpSignature rawSignature = new PgpSignature(
					new SignaturePacket(version, newPacketFormat: version == 6, signatureType, privKey.KeyId, keyAlgorithm,
						hashAlgorithm, hPkts, unhPkts, fingerPrint, m_salt, signature: null,
						signatureEncoding: sigBytes));
				m_generated = version == 6;
				return rawSignature;
			}

            if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
            {
                int sigLen = sigBytes.Length;
                if (sigLen == Ed25519.SignatureSize)
				{
					sigValues = new MPInteger[2]{
						new MPInteger(new BigInteger(1, sigBytes,  0, 32)),
						new MPInteger(new BigInteger(1, sigBytes, 32, 32))
					};
				}
                else if (sigLen == Ed448.SignatureSize)
                {
                    sigValues = new MPInteger[2]{
                        new MPInteger(new BigInteger(1, Arrays.Prepend(sigBytes, 0x40))),
                        new MPInteger(BigInteger.Zero)
                    };
                }
                else
				{
					throw new InvalidOperationException();
				}
            }
			else if (keyAlgorithm == PublicKeyAlgorithmTag.RsaSign || keyAlgorithm == PublicKeyAlgorithmTag.RsaGeneral)
			{
                sigValues = PgpUtilities.RsaSigToMpi(sigBytes);
            }
			else
			{
                sigValues = PgpUtilities.DsaSigToMpi(sigBytes);
            }

			if (version == 6)
			{
				m_generated = true;

				return new PgpSignature(
					new SignaturePacket(version, newPacketFormat: version == 6, signatureType, privKey.KeyId, keyAlgorithm,
						hashAlgorithm, hPkts, unhPkts, fingerPrint, m_salt, sigValues, signatureEncoding: null));
			}

            return new PgpSignature(
				new SignaturePacket(signatureType, privKey.KeyId, keyAlgorithm,
					hashAlgorithm, hPkts, unhPkts, fingerPrint, sigValues));
        }

		private static bool IsRawSignatureAlgorithm(PublicKeyAlgorithmTag algorithm)
		{
			switch (algorithm)
			{
			case PublicKeyAlgorithmTag.Ed25519:
			case PublicKeyAlgorithmTag.Ed448:
			case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
			case PublicKeyAlgorithmTag.MLDsa87_Ed448:
			case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
			case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
			case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
				return true;
			default:
				return false;
			}
		}

		/// <summary>Generate a certification for the passed in ID and key.</summary>
		/// <param name="id">The ID we are certifying against the public key.</param>
		/// <param name="pubKey">The key we are certifying against the ID.</param>
		/// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(string id, PgpPublicKey pubKey)
        {
			UpdateWithPublicKey(pubKey);

			//
            // hash in the id
            //
			UpdateWithIdData(0xb4, Strings.ToUtf8ByteArray(id));

            return Generate();
        }

        /// <summary>Generate a certification for a user ID given as raw octets.</summary>
        internal PgpSignature GenerateCertificationForRawId(byte[] rawId, PgpPublicKey pubKey)
        {
            UpdateWithPublicKey(pubKey);
            UpdateWithIdData(0xb4, rawId);

            return Generate();
        }

		/// <summary>Generate a certification for the passed in userAttributes.</summary>
		/// <param name="userAttributes">The ID we are certifying against the public key.</param>
		/// <param name="pubKey">The key we are certifying against the ID.</param>
		/// <returns>The certification.</returns>
		public PgpSignature GenerateCertification(PgpUserAttributeSubpacketVector userAttributes, PgpPublicKey pubKey)
		{
			UpdateWithPublicKey(pubKey);

			//
			// hash in the attributes
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

			return Generate();
		}

		/// <summary>Generate a certification for the passed in key against the passed in master key.</summary>
		/// <param name="masterKey">The key we are certifying against.</param>
		/// <param name="pubKey">The key we are certifying.</param>
		/// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey masterKey, PgpPublicKey pubKey)
        {
			CheckBinding(masterKey, pubKey);

			UpdateWithPublicKey(masterKey);
			UpdateWithPublicKey(pubKey);

			return Generate();
        }

		/// <summary>The rules for the signatures that bind a subkey and its primary key to each other.</summary>
		private void CheckBinding(PgpPublicKey masterKey, PgpPublicKey pubKey)
		{
			if (signatureType != PgpSignature.SubkeyBinding && signatureType != PgpSignature.PrimaryKeyBinding)
				return;

			// RFC 9580 10.1.1, 10.1.3: the subkeys of a key have the version of the primary key
			if (masterKey.Version != pubKey.Version)
				throw new PgpException("a subkey has to have the version of its primary key");

			// RFC 9980 7.2: no weak hashes in the binding signatures of subkeys of the RFC 9980 algorithms
			if (signatureType == PgpSignature.SubkeyBinding && PgpUtilities.IsRfc9980Algorithm(pubKey.Algorithm) &&
				PgpUtilities.IsWeakBindingHash(hashAlgorithm))
			{
				throw new PgpException("hash algorithm not allowed for subkey bindings of " + pubKey.Algorithm + ": "
					+ hashAlgorithm);
			}
		}

		/// <summary>Generate a certification, such as a revocation, for the passed in key.</summary>
		/// <param name="pubKey">The key we are certifying.</param>
		/// <returns>The certification.</returns>
        public PgpSignature GenerateCertification(PgpPublicKey pubKey)
        {
			UpdateWithPublicKey(pubKey);

			return Generate();
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

		private static bool HasNonCriticalNonExportable(SignatureSubpacket[] packets)
		{
			foreach (SignatureSubpacket packet in packets)
			{
				if (packet.SubpacketType == SignatureSubpacketTag.Exportable && !packet.IsCritical() &&
					packet.Data.Length > 0 && packet.Data[0] == 0)
				{
					return true;
				}
			}
			return false;
		}

		private static bool HasIssuerFingerprintOfOtherVersion(SignatureSubpacket[] packets)
		{
			foreach (SignatureSubpacket packet in packets)
			{
				if (packet.SubpacketType == SignatureSubpacketTag.IssuerFingerprint && packet.Data.Length > 0 &&
					packet.Data[0] != PublicKeyPacket.Version6)
				{
					return true;
				}
			}
			return false;
		}

		private static bool IsPacketPresent(SignatureSubpacket[] packets, SignatureSubpacketTag type)
		{
			for (int i = 0; i != packets.Length; i++)
			{
				if (packets[i].SubpacketType == type)
					return true;
			}

			return false;
		}

		private static SignatureSubpacket[] InsertSubpacket(SignatureSubpacket[] packets, SignatureSubpacket subpacket)
		{
			return Arrays.Prepend(packets, subpacket);
		}

		private void UpdateWithIdData(int header, byte[] idBytes)
		{
			Update(
				(byte) header,
				(byte)(idBytes.Length >> 24),
				(byte)(idBytes.Length >> 16),
				(byte)(idBytes.Length >> 8),
				(byte)(idBytes.Length));
			Update(idBytes);
		}

		private void UpdateWithPublicKey(
			PgpPublicKey key)
		{
			byte[] keyBytes = GetEncodedPublicKey(key);

			if (m_version == 6)
			{
				// RFC 9580 5.2.4: 0x9B and a 4-octet length for version 6 signatures
				Update(
					0x9B,
					(byte)(keyBytes.Length >> 24),
					(byte)(keyBytes.Length >> 16),
					(byte)(keyBytes.Length >> 8),
					(byte)(keyBytes.Length));
			}
			else
			{
				Update(
					0x99,
					(byte)(keyBytes.Length >> 8),
					(byte)(keyBytes.Length));
			}
			Update(keyBytes);
		}
	}
}
