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
		private static readonly SignatureSubpacket[] EmptySignatureSubpackets = Array.Empty<SignatureSubpacket>();

		private readonly PublicKeyAlgorithmTag keyAlgorithm;
        private readonly HashAlgorithmTag hashAlgorithm;

		private int version;

        private PgpPrivateKey			privKey;
        private ISigner					sig;
        private readonly IDigest		dig;
        private int						signatureType;
        private byte					lastb;

		private byte[] salt;

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
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-signature-packet-type-id-2
            // An implementation MUST generate a version 6 signature when signing with a version 6 key.
			// An implementation MUST generate a version 4 signature when signing with a version 4 key. 
            this.version = privKey.Version;
			this.privKey = privKey;
			this.signatureType = sigType;

			AsymmetricKeyParameter key = privKey.Key;

            this.sig = PgpUtilities.CreateSigner(keyAlgorithm, hashAlgorithm, key);

            try
			{
				ICipherParameters cp = key;

				// TODO Ask SignerUtilities whether random is permitted?
				if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy
					|| keyAlgorithm == PublicKeyAlgorithmTag.Ed25519
					|| keyAlgorithm == PublicKeyAlgorithmTag.Ed448)
				{
					// EdDSA signers don't expect a SecureRandom
				}
				else
				{
                    cp = ParameterUtilities.WithRandom(cp, random);
                }

				sig.Init(true, cp);

				// salt for v6 signatures
				if(version == SignaturePacket.Version6)
				{
                    if (random is null)
					{
						throw new ArgumentNullException(nameof(random), "v6 signatures requires a SecureRandom() for salt generation");
					}
					int saltSize = PgpUtilities.GetSaltSize(hashAlgorithm);
					salt = new byte[saltSize];
					random.NextBytes(salt);
                    sig.BlockUpdate(salt, 0, salt.Length);
                }
			}
			catch (InvalidKeyException e)
			{
				throw new PgpException("invalid key.", e);
			}

			dig.Reset();
			lastb = 0;
		}

		public void Update(byte b)
        {
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
			OnePassSignaturePacket opsPkt;

            // the versions of the Signature and the One-Pass Signature must be aligned as specified in
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#signed-message-versions
            if (version == SignaturePacket.Version6)
			{
				opsPkt = new OnePassSignaturePacket(
					signatureType, hashAlgorithm, keyAlgorithm, salt, privKey.GetFingerprint(), isNested);

            }
			else
			{
                opsPkt = new OnePassSignaturePacket(
					signatureType, hashAlgorithm, keyAlgorithm, privKey.KeyId, isNested);
            }

            return new PgpOnePassSignature(opsPkt);
        }

		/// <summary>Return a signature object containing the current signature state.</summary>
        public PgpSignature Generate()
        {
			SignatureSubpacket[] hPkts = hashed, unhPkts = unhashed;

			if (!IsPacketPresent(hashed, SignatureSubpacketTag.CreationTime))
			{
				hPkts = InsertSubpacket(hPkts, new SignatureCreationTime(false, DateTime.UtcNow));
			}

            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-issuer-key-id
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#issuer-fingerprint-subpacket
            bool containsIssuerKeyId = IsPacketPresent(hashed, SignatureSubpacketTag.IssuerKeyId) || IsPacketPresent(unhashed, SignatureSubpacketTag.IssuerKeyId);
            bool containsIssuerKeyFpr = IsPacketPresent(hashed, SignatureSubpacketTag.IssuerFingerprint) || IsPacketPresent(unhashed, SignatureSubpacketTag.IssuerFingerprint);
            switch (version)
            {
                case SignaturePacket.Version4:
                    // TODO enforce constraint: if a v4 signature contains both IssuerKeyId and IssuerFingerprint
                    // subpackets, then the KeyId MUST match the low 64 bits of the fingerprint.
                    if (!containsIssuerKeyId)
					{
                        unhPkts = InsertSubpacket(unhPkts, new IssuerKeyId(false, privKey.KeyId));
                    }
                    break;
                case SignaturePacket.Version6:
					// V6 signatures MUST NOT include an IssuerKeyId subpacket and SHOULD include an IssuerFingerprint subpacket
					if (containsIssuerKeyId)
					{
                        // TODO enforce constraint: v6 signatures MUST NOT include an IssuerKeyId subpacket
                    }
                    if (!containsIssuerKeyFpr)
                    {
                        unhPkts = InsertSubpacket(unhPkts, new IssuerFingerprint(false, privKey.Version, privKey.GetFingerprint()));
                    }
                    break;
            }

			byte[] hData;

			try
            {
				using (MemoryStream hOut = new MemoryStream())
				{

					for (int i = 0; i != hPkts.Length; i++)
					{
						hPkts[i].Encode(hOut);
					}

					byte[] data = hOut.ToArray();

					using (MemoryStream sOut = new MemoryStream(data.Length + 6))
					{
						sOut.WriteByte((byte)version);
						sOut.WriteByte((byte)signatureType);
						sOut.WriteByte((byte)keyAlgorithm);
						sOut.WriteByte((byte)hashAlgorithm);
						if (version == SignaturePacket.Version6)
						{
                            sOut.WriteByte((byte)(data.Length >> 24));
                            sOut.WriteByte((byte)(data.Length >> 16));
                        }
						sOut.WriteByte((byte)(data.Length >> 8));
						sOut.WriteByte((byte)data.Length);
						sOut.Write(data, 0, data.Length);

						hData = sOut.ToArray();
					}
				}
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

			SignaturePacket sigPkt;

			if (keyAlgorithm == PublicKeyAlgorithmTag.Ed25519 || keyAlgorithm == PublicKeyAlgorithmTag.Ed448)
			{
				sigPkt = new SignaturePacket(
					version,
					signatureType,
					privKey.KeyId,
					keyAlgorithm,
					hashAlgorithm,
					hPkts,
					unhPkts,
					fingerPrint,
					version == SignaturePacket.Version6 ? salt : null,
					privKey.GetFingerprint(),
					sigBytes);
			}
			else
			{
				MPInteger[] sigValues;
				if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy)
				{
					int sigLen = sigBytes.Length;

					if (sigLen == Ed25519.SignatureSize)
					{
						sigValues = new MPInteger[2]
						{
							new MPInteger(new BigInteger(1, sigBytes,  0, 32)),
							new MPInteger(new BigInteger(1, sigBytes, 32, 32))
						};
					}
					else if (sigLen == Ed448.SignatureSize)
					{
						sigValues = new MPInteger[2]
						{
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

				sigPkt = new SignaturePacket(
					version,
					signatureType,
					privKey.KeyId,
					keyAlgorithm,
					hashAlgorithm,
					hPkts,
					unhPkts,
					fingerPrint,
					version == SignaturePacket.Version6 ? salt : null,
					privKey.GetFingerprint(),
					sigValues);
            }

			return new PgpSignature(sigPkt);
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
			UpdateWithPublicKey(masterKey);
			UpdateWithPublicKey(pubKey);

			return Generate();
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

            this.Update(PgpPublicKey.FingerprintPreamble(version));

            switch (version)
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
	}
}
