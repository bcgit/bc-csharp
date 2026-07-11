using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP secret key.</remarks>
    public class SecretKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        public const int UsageNone = 0x00;
        public const int UsageChecksum = 0xff;
        public const int UsageSha1 = 0xfe;
        public const int UsageAead = 0xfd;

        private PublicKeyPacket pubKeyPacket;
        private readonly byte[] secKeyData;
        private int s2kUsage;
        private SymmetricKeyAlgorithmTag encAlgorithm;
        private AeadAlgorithmTag aeadAlgorithm;
        private S2k s2k;
        private byte[] iv;

        internal SecretKeyPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SecretKeyPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : this(PacketTag.SecretKey, bcpgIn, newPacketFormat)
        {
        }

        internal SecretKeyPacket(PacketTag keyTag, BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(keyTag, newPacketFormat)
        {
            if (this is SecretSubkeyPacket)
            {
                pubKeyPacket = new PublicSubkeyPacket(bcpgIn, newPacketFormat);
            }
            else
            {
                pubKeyPacket = new PublicKeyPacket(bcpgIn, newPacketFormat);
            }

            byte version = pubKeyPacket.VersionByte;
            s2kUsage = bcpgIn.RequireByte();

            int conditionalParameterLength = -1;
            if (version == PublicKeyPacket.LibrePgp5 ||
               (version == PublicKeyPacket.Version6 && s2kUsage != UsageNone))
            {
                // TODO: Use length to parse unknown parameters
                conditionalParameterLength = bcpgIn.RequireByte();
            }

            if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1 || s2kUsage == UsageAead)
            {
                encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
            }
            else
            {
                encAlgorithm = (SymmetricKeyAlgorithmTag)s2kUsage;
            }

            if (s2kUsage == UsageAead)
            {
                aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.RequireByte();
            }

            if (version == PublicKeyPacket.Version6 && (s2kUsage == UsageSha1 || s2kUsage == UsageAead))
            {
                int s2KLen = bcpgIn.RequireByte();
                byte[] s2kBytes = new byte[s2KLen];
                bcpgIn.ReadFully(s2kBytes);

                try
                {
                    s2k = new S2k(new MemoryStream(s2kBytes, false));
                }
                catch (UnsupportedPacketVersionException e)
                {
                    throw new MalformedPacketException("Unsupported S2K type", e);
                }
            }
            else if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1 || s2kUsage == UsageAead)
            {
                s2k = new S2k(bcpgIn);
            }

            if (s2kUsage == UsageAead)
            {
                try
                {
                    iv = new byte[AeadUtilities.GetIVLength(aeadAlgorithm)];
                }
                catch (ArgumentException e)
                {
                    throw new MalformedPacketException("Unknown AEAD algorithm", e);
                }
                bcpgIn.ReadFully(iv);
            }
            else
            {
                bool isGnuDummyNoPrivateKey =
                    s2k != null &&
                    s2k.Type == S2k.GnuDummyS2K &&
                    s2k.ProtectionMode == S2k.GnuProtectionModeNoPrivateKey;

                if (!isGnuDummyNoPrivateKey)
                {
                    if (s2kUsage != UsageNone)
                    {
                        if (((int)encAlgorithm) < 7)
                        {
                            iv = new byte[8];
                        }
                        else
                        {
                            iv = new byte[16];
                        }
                        bcpgIn.ReadFully(iv);
                    }
                }
            }

            if (version == PublicKeyPacket.LibrePgp5)
            {
                long keyOctetCount = StreamUtilities.RequireUInt32BE(bcpgIn);
                if (s2kUsage == UsageChecksum || s2kUsage == UsageNone)
                {
                    // encoded keyOctetCount does not contain checksum
                    keyOctetCount += 2;
                }

                if (keyOctetCount > PublicKeyPacket.MaxLength)
                    throw new MalformedPacketException(
                        $"Key octet count ({keyOctetCount}) exceeds limit ({PublicKeyPacket.MaxLength}).");

                secKeyData = new byte[(int)keyOctetCount];
                bcpgIn.ReadFully(secKeyData);
            }
            else
            {
                secKeyData = bcpgIn.ReadAll();
            }
        }

        public SecretKeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] iv,
            byte[] secKeyData)
            : this(PacketTag.SecretKey, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
        {
        }

        /// <summary>Construct a <see cref="SecretKeyPacket"/> or <see cref="SecretSubkeyPacket"/>.</summary>
        /// <remarks>
        /// <paramref name="secKeyData"/> needs to be prepared by applying encryption/checksum beforehand.
        /// </remarks>
        /// <param name="keyTag">Packet type ID.</param>
        /// <param name="pubKeyPacket">Pubkey packet corresponding to this secret key packet.</param>
        /// <param name="encAlgorithm">Algorithm ID of the symmetric key algorithm that was used to encrypt the secret
        /// key material.</param>
        /// <param name="s2k">S2k identifier for deriving a key from a passphrase.</param>
        /// <param name="iv">IV that was used to encrypt the secret key material.</param>
        /// <param name="secKeyData">Encrypted/checksum'd secret key material.</param>
        internal SecretKeyPacket(PacketTag keyTag, PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm,
            S2k s2k, byte[] iv, byte[] secKeyData)
            : this(keyTag, pubKeyPacket, encAlgorithm, 0,
                  encAlgorithm != SymmetricKeyAlgorithmTag.Null ? UsageChecksum : UsageNone, s2k, iv, secKeyData)
        {
        }

        public SecretKeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2kUsage,
            S2k s2k, byte[] iv, byte[] secKeyData)
            : this(PacketTag.SecretKey, pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData)
        {
        }

        /// <summary>Construct a <see cref="SecretKeyPacket"/> or <see cref="SecretSubkeyPacket"/>.</summary>
        /// <remarks>
        /// <paramref name="secKeyData"/> needs to be prepared by applying encryption/checksum beforehand.
        /// </remarks>
        /// <param name="pubKeyPacket">Pubkey packet corresponding to this secret key packet.</param>
        /// <param name="encAlgorithm">Algorithm ID of the symmetric key algorithm that was used to encrypt the secret
        /// key material.</param>
        /// <param name="aeadAlgorithm">AEAD algorithm scheme used to protect the secret key material.</param>
        /// <param name="s2k">S2k identifier for deriving a key from a passphrase.</param>
        /// <param name="iv">IV that was used to encrypt the secret key material.</param>
        /// <param name="secKeyData">Encrypted/checksum'd secret key material.</param>
        public SecretKeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int s2kUsage, S2k s2k, byte[] iv, byte[] secKeyData)
            : this(PacketTag.SecretKey, pubKeyPacket, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, secKeyData)
        {
        }

        /// <summary>Construct a <see cref="SecretKeyPacket"/> or <see cref="SecretSubkeyPacket"/>.</summary>
        /// <remarks>
        /// <paramref name="secKeyData"/> needs to be prepared by applying encryption/checksum beforehand.
        /// </remarks>
        /// <param name="keyTag">Packet type ID.</param>
        /// <param name="pubKeyPacket">Pubkey packet corresponding to this secret key packet.</param>
        /// <param name="encAlgorithm">Algorithm ID of the symmetric key algorithm that was used to encrypt the secret
        /// key material.</param>
        /// <param name="aeadAlgorithm">AEAD algorithm scheme used to protect the secret key material.</param>
        /// <param name="s2kUsage">octet indicating how the secret key material was encrypted.</param>
        /// <param name="s2k">S2k identifier for deriving a key from a passphrase.</param>
        /// <param name="iv">IV that was used to encrypt the secret key material.</param>
        /// <param name="secKeyData">Encrypted/checksum'd secret key material.</param>
        internal SecretKeyPacket(PacketTag keyTag, PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int s2kUsage, S2k s2k, byte[] iv, byte[] secKeyData)
            : base(keyTag, pubKeyPacket.HasNewPacketFormat)
        {
            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;
            this.aeadAlgorithm = aeadAlgorithm;
            this.s2kUsage = s2kUsage;
            this.s2k = s2k;
            this.iv = Arrays.Clone(iv);
            this.secKeyData = secKeyData;

            if (s2k != null && s2k.Type == S2k.Argon2 && s2kUsage != UsageAead)
                throw new ArgumentException("Argon2 is only used with AEAD (S2K usage octet 253)");

            if (pubKeyPacket.VersionByte == PublicKeyPacket.Version6)
            {
                if (s2kUsage == UsageChecksum)
                    throw new ArgumentException("Version 6 keys MUST NOT use S2K usage USAGE_CHECKSUM");
            }
        }

        public SymmetricKeyAlgorithmTag EncAlgorithm => encAlgorithm;

        public AeadAlgorithmTag AeadAlgorithm => aeadAlgorithm;

        public int S2kUsage => s2kUsage;

        public byte[] GetIV() => Arrays.Clone(iv);

        public S2k S2k => s2k;

        public PublicKeyPacket PublicKeyPacket => pubKeyPacket;

        public byte[] GetSecretKeyData() => secKeyData;

        public byte[] GetEncodedContents()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.Write(pubKeyPacket.GetEncodedContents());
                pOut.WriteByte((byte)s2kUsage);

                // conditional parameters
                byte[] conditionalParameters = EncodeConditionalParameters();
                if (pubKeyPacket.VersionByte == PublicKeyPacket.LibrePgp5 ||
                   (pubKeyPacket.VersionByte == PublicKeyPacket.Version6 && s2kUsage != UsageNone))
                {
                    pOut.Write((byte)conditionalParameters.Length);
                }
                pOut.Write(conditionalParameters);

                if (secKeyData != null && secKeyData.Length > 0)
                {
                    if (pubKeyPacket.VersionByte == PublicKeyPacket.LibrePgp5)
                    {
                        int keyOctetCount = secKeyData.Length;
                        // v5 keyOctetCount does not include checksum octets
                        if (s2kUsage == UsageChecksum || s2kUsage == UsageNone)
                        {
                            keyOctetCount -= 2;
                        }
                        StreamUtilities.WriteUInt32BE(pOut, (uint)keyOctetCount);
                    }
                    pOut.Write(secKeyData);
                }
            }
            return bOut.ToArray();
        }

        private byte[] EncodeConditionalParameters()
        {
            MemoryStream conditionalParameters = new MemoryStream();
            bool hasS2KSpecifier = s2kUsage == UsageChecksum || s2kUsage == UsageSha1 || s2kUsage == UsageAead;

            if (hasS2KSpecifier)
            {
                conditionalParameters.WriteByte((byte)encAlgorithm);
                if (s2kUsage == UsageAead)
                {
                    conditionalParameters.WriteByte((byte)aeadAlgorithm);
                }
                byte[] encodedS2K = s2k.GetEncoded();
                if (pubKeyPacket.VersionByte == PublicKeyPacket.Version6)
                {
                    conditionalParameters.WriteByte((byte)encodedS2K.Length);
                }
                conditionalParameters.Write(encodedS2K, 0, encodedS2K.Length);
            }
            if (iv != null)
            {
                // since UsageAead and other types that use an IV are mutually exclusive,
                // we use the IV field for both v4 IVs and v6 AEAD nonces
                conditionalParameters.Write(iv, 0, iv.Length);
            }

            return conditionalParameters.ToArray();
        }

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag, GetEncodedContents());
    }
}
