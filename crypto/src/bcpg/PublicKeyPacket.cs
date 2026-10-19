using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        /// <summary>The maximum length of a public key packet body that is accepted.</summary>
        public static readonly int MaxLength = 2 * 1024 * 1024; // 2MiB; e.g. McEliece keys can get ~1MiB in size

        /// <summary>OpenPGP v3 keys are deprecated. They can only be used with RSA.</summary>
        /// <remarks>
        /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-3-public-keys">
        /// OpenPGP - Version 3 Public Keys
        /// </see>
        /// </remarks>
        public static readonly byte Version3 = 3;

        /// <summary>
        /// OpenPGP v4 keys are (at the time of writing) widely used, but are subject to some attacks.
        /// </summary>
        /// <remarks>
        /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-4-public-keys">
        /// OpenPGP - Version 4 Public Keys
        /// </see>
        /// </remarks>
        public static readonly byte Version4 = 4;

        /// <summary>Non-Standard LibrePGP introduced v5, which is only supported by a subset of vendors.</summary>
        public static readonly byte LibrePgp5 = 5;

        /// <summary>OpenPGP v6 keys are newly introduced.</summary>
        /// <remarks>
        /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-public-keys">
        /// OpenPGP - Version 6 Public Keys
        /// </see>
        /// </remarks>
        public static readonly byte Version6 = 6;

        private readonly byte m_version;
        private readonly long m_time;
        private readonly int m_validDays;
        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly IBcpgKey m_key;

        internal PublicKeyPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal PublicKeyPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : this(PacketTag.PublicKey, bcpgIn, newPacketFormat: false)
        {
        }

        internal PublicKeyPacket(PacketTag keyTag, BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(keyTag, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
            if (m_version < 2 || m_version > Version6)
                throw new UnsupportedPacketVersionException(
                    $"Unsupported Public Key Packet version encountered: {m_version}");

            m_time = StreamUtilities.RequireUInt32BE(bcpgIn);

            if (m_version <= Version3)
            {
                m_validDays = StreamUtilities.RequireUInt16BE(bcpgIn);
            }

            m_algorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();

            long keyOctets = -1;
            if (m_version == LibrePgp5 || m_version == Version6)
            {
                // TODO: Use keyOctets to be able to parse unknown keys
                keyOctets = StreamUtilities.RequireUInt32BE(bcpgIn);
                if (keyOctets > int.MaxValue)
                    throw new MalformedPacketException("Octet length exceeds limit.");
            }

            m_key = ParseKey(bcpgIn, m_algorithm, keyOctets);
        }

        /**
         * Parse algorithm-specific public key material.
         * @param in input stream which read just up to the public key material
         * @param algorithmId public key algorithm ID
         * @param optLen optional: Length of the public key material. -1 if not present.
         * @throws IOException if the pk material cannot be parsed
         */
        private IBcpgKey ParseKey(BcpgInputStream bcpgIn, PublicKeyAlgorithmTag algorithm, long optLen)
        {
            try
            {
                switch (algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    return new RsaPublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.Dsa:
                    return new DsaPublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return new ElGamalPublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.ECDH:
                    return new ECDHPublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.X25519:
                    return new X25519PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.X448:
                    return new X448PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.ECDsa:
                    return new ECDsaPublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.EdDsa_Legacy:
                    return new EdDsaPublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.Ed25519:
                    return new Ed25519PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.Ed448:
                    return new Ed448PublicBcpgKey(bcpgIn);
                default:
                    if (m_version == LibrePgp5 || m_version == Version6)
                    {
                        // with version 5 & 6, we can gracefully handle unknown key types, as the length is known.
                        return new UnknownBcpgKey((int)optLen, bcpgIn);
                    }
                    throw new IOException("Unknown PGP public key algorithm encountered: " + algorithm);
                }
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new MalformedPacketException("Malformed PGP key.", e);
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        [Obsolete("Use constructor with additional 'version' parameter instead")]
        public PublicKeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
            : this(Version4, algorithm, time, key)
        {
        }

        /// <summary>Create a new <see cref="PublicKeyPacket"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="time">The time.</param>
        /// <param name="key">The key.</param>
        public PublicKeyPacket(byte version, PublicKeyAlgorithmTag algorithm, DateTime time,
            IBcpgKey key)
            : this(PacketTag.PublicKey, version, algorithm, time, key)
        {
        }

        internal PublicKeyPacket(PacketTag keyTag, byte version, PublicKeyAlgorithmTag algorithm, DateTime time,
            IBcpgKey key)
            : base(keyTag)
        {
            m_version = version;
            m_time = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            m_algorithm = algorithm;
            m_key = key;
        }

        /// <summary>Gets the version.</summary>
        public virtual int Version => m_version;

        /// <summary>Gets the version byte.</summary>
        public virtual byte VersionByte => m_version;

        /// <summary>Gets the algorithm.</summary>
        public virtual PublicKeyAlgorithmTag Algorithm => m_algorithm;

        /// <summary>Gets the valid days.</summary>
        public virtual int ValidDays => m_validDays;

        /// <summary>Return the time.</summary>
        public virtual DateTime GetTime() => DateTimeUtilities.UnixMsToDateTime(m_time * 1000L);

        /// <summary>Gets the key.</summary>
        public virtual IBcpgKey Key => m_key;

        /// <summary>Return the encoded contents.</summary>
        public virtual byte[] GetEncodedContents()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte(m_version);
                StreamUtilities.WriteUInt32BE(pOut, (uint)m_time);

                if (m_version <= Version3)
                {
                    StreamUtilities.WriteUInt16BE(pOut, (ushort)m_validDays);
                }

                pOut.WriteByte((byte)m_algorithm);

                if (m_version == Version6 || m_version == LibrePgp5)
                {
                    byte[] keyEncoding = ((BcpgObject)m_key).GetEncoded();
                    StreamUtilities.WriteUInt32BE(pOut, (uint)keyEncoding.Length);
                    pOut.Write(keyEncoding);
                }
                else
                {
                    ((BcpgObject)m_key).Encode(pOut);
                }
            }
            return bOut.ToArray();
        }

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag, GetEncodedContents());

        /// <summary>Calculate the key ID of a public key packet.</summary>
        /// <param name="publicPk">The packet.</param>
        /// <param name="fingerprint">The fingerprint of the key.</param>
        /// <returns>The key ID.</returns>
        public static long GetKeyID(PublicKeyPacket publicPk, byte[] fingerprint)
        {
            byte version = publicPk.VersionByte;
            if (version <= Version3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)publicPk.m_key;

                return rK.Modulus.LongValue;
            }

            return FingerprintUtilities.KeyIDFromFingerprint(version, fingerprint);
        }
    }
}
