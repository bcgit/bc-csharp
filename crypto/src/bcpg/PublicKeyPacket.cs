using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
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
            : this(PacketTag.PublicKey, bcpgIn, newPacketFormat)
        {
        }

        internal PublicKeyPacket(PacketTag keyTag, BcpgInputStream bcpgIn, bool newPacketFormat)
            : this(keyTag, bcpgIn, newPacketFormat, insideSecretKey: false)
        {
            // RFC 9580 5.5.2.3: nothing follows the key material of a version 6 key, which the fingerprint would
            // not cover
            if (m_version == Version6 && bcpgIn.ReadByte() >= 0)
                throw new MalformedPacketException("Trailing data after the public key material.");
        }

        /// <param name="insideSecretKey">
        /// Whether this packet is the public part of a secret key packet, where the end of the public key material
        /// cannot be determined for key types that this implementation does not know.
        /// </param>
        internal PublicKeyPacket(PacketTag keyTag, BcpgInputStream bcpgIn, bool newPacketFormat,
            bool insideSecretKey)
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

            if (m_version == Version6)
            {
                // RFC 9580 5.5.2.3: the key material has exactly the length that the packet gives
                byte[] material = ReadKeyMaterial(bcpgIn, keyOctets);
                var input = BcpgInputStream.Wrap(new MemoryStream(material, false));
                m_key = ParseKey(input, m_algorithm, keyOctets, insideSecretKey);
                if (input.ReadByte() >= 0)
                    throw new MalformedPacketException("Trailing data after the public key material.");
            }
            else
            {
                m_key = ParseKey(bcpgIn, m_algorithm, keyOctets, insideSecretKey);
            }
        }

        /// <summary>
        /// Read key material of the given length, in pieces, so that a length beyond the end of the packet only
        /// costs the memory of the data that is actually there.
        /// </summary>
        private static byte[] ReadKeyMaterial(BcpgInputStream bcpgIn, long length)
        {
            var material = new MemoryStream();
            byte[] buffer = new byte[4096];
            while (material.Length < length)
            {
                int count = bcpgIn.Read(buffer, 0, (int)System.Math.Min(buffer.Length, length - material.Length));
                if (count <= 0)
                    throw new MalformedPacketException("Truncated public key material.");

                material.Write(buffer, 0, count);
            }
            return material.ToArray();
        }

        /**
         * Parse algorithm-specific public key material.
         * @param in input stream which read just up to the public key material
         * @param algorithmId public key algorithm ID
         * @param optLen optional: Length of the public key material. -1 if not present.
         * @throws IOException if the pk material cannot be parsed
         */
        private IBcpgKey ParseKey(BcpgInputStream bcpgIn, PublicKeyAlgorithmTag algorithm, long optLen,
            bool insideSecretKey)
        {
            // RFC 9580 3.2: MPIs in version 6 key packets must be minimally encoded
            bool strictMpis = m_version == Version6;

            // RFC 9580 5.2.3.3, 12.5, 12.6: DSA, Elgamal and EdDSALegacy are not for version 6 keys. Their key
            // material is kept opaque, so that such a key cannot be used while the rest of the certificate can.
            if (m_version == Version6 && IsVersion4OnlyAlgorithm(algorithm))
                return new UnknownBcpgKey((int)optLen, bcpgIn);

            try
            {
                switch (algorithm)
                {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    return new RsaPublicBcpgKey(bcpgIn, strictMpis);
                case PublicKeyAlgorithmTag.Dsa:
                    return new DsaPublicBcpgKey(bcpgIn, strictMpis);
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    return new ElGamalPublicBcpgKey(bcpgIn, strictMpis);
                case PublicKeyAlgorithmTag.ECDH:
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.EdDsa_Legacy:
                {
                    IBcpgKey ecKey = ParseECKey(bcpgIn, algorithm, optLen, insideSecretKey, strictMpis);

                    // RFC 9580 5.5.5.6.1.1: nor is Curve25519Legacy (or ECDH over the other Montgomery curves)
                    if (m_version == Version6 && ecKey is ECDHPublicBcpgKey ecdhKey &&
                        IsVersion4OnlyEcdhCurve(ecdhKey.CurveOid))
                    {
                        byte[] material = ecdhKey.GetEncoded();
                        return new UnknownBcpgKey(material.Length, material);
                    }
                    return ecKey;
                }
                case PublicKeyAlgorithmTag.X25519:
                    RequireKeyLength(optLen, X25519PublicBcpgKey.Length);
                    return new X25519PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.X448:
                    RequireKeyLength(optLen, X448PublicBcpgKey.Length);
                    return new X448PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.Ed25519:
                    RequireKeyLength(optLen, Ed25519PublicBcpgKey.Length);
                    return new Ed25519PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.Ed448:
                    RequireKeyLength(optLen, Ed448PublicBcpgKey.Length);
                    return new Ed448PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.MLKem768_X25519
                    when m_version == Version6 || (m_version == Version4 && PacketTag == PacketTag.PublicSubkey):
                    // RFC 9980 3.5, 4.3.2: only defined for v6 keys and v4 (encryption) subkeys
                    RequireKeyLength(optLen, MLKem768X25519PublicBcpgKey.Length);
                    return new MLKem768X25519PublicBcpgKey(bcpgIn);

                // RFC 9980 3.5: the following algorithms are only defined for v6 keys
                case PublicKeyAlgorithmTag.MLKem1024_X448 when m_version == Version6:
                    RequireKeyLength(optLen, MLKem1024X448PublicBcpgKey.Length);
                    return new MLKem1024X448PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.MLDsa65_Ed25519 when m_version == Version6:
                    RequireKeyLength(optLen, MLDsa65Ed25519PublicBcpgKey.Length);
                    return new MLDsa65Ed25519PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.MLDsa87_Ed448 when m_version == Version6:
                    RequireKeyLength(optLen, MLDsa87Ed448PublicBcpgKey.Length);
                    return new MLDsa87Ed448PublicBcpgKey(bcpgIn);
                case PublicKeyAlgorithmTag.SlhDsa_Shake128s when m_version == Version6:
                case PublicKeyAlgorithmTag.SlhDsa_Shake128f when m_version == Version6:
                case PublicKeyAlgorithmTag.SlhDsa_Shake256s when m_version == Version6:
                    RequireKeyLength(optLen, SlhDsaPublicBcpgKey.GetKeyLength(algorithm));
                    return new SlhDsaPublicBcpgKey(algorithm, bcpgIn);
                default:
                    if (m_version == LibrePgp5 || m_version == Version6)
                    {
                        // with version 5 & 6, we can gracefully handle unknown key types, as the length is known.
                        return new UnknownBcpgKey((int)optLen, bcpgIn);
                    }

                    if (!insideSecretKey)
                    {
                        // The key material of a v4 public key packet extends to the end of the packet
                        byte[] unknownKey = bcpgIn.ReadAll();
                        return new UnknownBcpgKey(unknownKey.Length, unknownKey);
                    }

                    if (IsVersion6OnlyAlgorithm(algorithm))
                        throw new MalformedPacketException("Algorithm only defined for version 6 keys: " + algorithm);
                    if (algorithm == PublicKeyAlgorithmTag.MLKem768_X25519)
                    {
                        throw new MalformedPacketException(
                            "Algorithm only defined for version 6 keys and version 4 subkeys: " + algorithm);
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

        private static IBcpgKey CreateECKey(PublicKeyAlgorithmTag algorithm, BcpgInputStream bcpgIn, bool strictMpis)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.ECDH:
                return new ECDHPublicBcpgKey(bcpgIn, strictMpis);
            case PublicKeyAlgorithmTag.ECDsa:
                return new ECDsaPublicBcpgKey(bcpgIn, strictMpis);
            default:
                return new EdDsaPublicBcpgKey(bcpgIn);
            }
        }

        /// <summary>
        /// Parse ECDH, ECDSA or EdDSALegacy key material. Key material on a curve that this implementation does not
        /// know, in an encoding that cannot be parsed (for example a placeholder for a future algorithm), is kept
        /// opaque, so that the rest of the certificate stays usable. This is only possible where the end of the key
        /// material is known: in v5/v6 packets (the key material length) and in v4 public key packets (the end of the
        /// packet). Malformed key material on a known curve is still an error.
        /// </summary>
        private static IBcpgKey ParseECKey(BcpgInputStream bcpgIn, PublicKeyAlgorithmTag algorithm, long optLen,
            bool insideSecretKey, bool strictMpis)
        {
            if (optLen < 0 && insideSecretKey)
                return CreateECKey(algorithm, bcpgIn, strictMpis);

            byte[] material;
            if (optLen >= 0)
            {
                material = new byte[optLen];
                bcpgIn.ReadFully(material);
            }
            else
            {
                material = bcpgIn.ReadAll();
            }

            try
            {
                var input = BcpgInputStream.Wrap(new MemoryStream(material, false));
                IBcpgKey key = CreateECKey(algorithm, input, strictMpis);
                if (input.ReadByte() < 0)
                    return key;

                if (IsKnownCurve(material))
                {
                    // v5/v6 key material has an exact length (RFC 9580 5.5.2.3); v4 stays as lenient as it was
                    if (optLen >= 0)
                        throw new MalformedPacketException("Trailing data after the public key material.");
                    return key;
                }
            }
            catch (Exception) when (!IsKnownCurve(material))
            {
                // an unknown curve in an encoding that cannot be parsed: kept opaque (below)
            }

            return new UnknownBcpgKey(material.Length, material);
        }

        /// <summary>
        /// Whether the key material starts with the OID of a curve that this implementation supports.
        /// </summary>
        private static bool IsKnownCurve(byte[] material)
        {
            if (material.Length < 1 || material[0] == 0 || material[0] == 0xFF || material.Length < 1 + material[0])
                return false;

            DerObjectIdentifier oid;
            try
            {
                byte[] encoding = new byte[2 + material[0]];
                encoding[0] = 0x06;
                encoding[1] = material[0];
                Array.Copy(material, 1, encoding, 2, material[0]);
                oid = DerObjectIdentifier.GetInstance(encoding);
            }
            catch (Exception)
            {
                return false;
            }

            return ECUtilities.FindECCurveByOidLazy(oid) != null
                || EdECObjectIdentifiers.id_X25519.Equals(oid) || EdECObjectIdentifiers.id_X448.Equals(oid)
                || EdECObjectIdentifiers.id_Ed25519.Equals(oid) || EdECObjectIdentifiers.id_Ed448.Equals(oid)
                || CryptlibObjectIdentifiers.curvey25519.Equals(oid) || GnuObjectIdentifiers.Ed25519.Equals(oid);
        }

        private static void RequireKeyLength(long optLen, int expected)
        {
            if (optLen >= 0 && optLen != expected)
                throw new MalformedPacketException("Invalid public key material length: " + optLen);
        }

        /// <summary>The algorithms that RFC 9580 does not allow in version 6 keys.</summary>
        private static bool IsVersion4OnlyAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.Dsa:
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                return true;
            default:
                return false;
            }
        }

        /// <summary>
        /// The ECDH curves that are not for version 6 keys: Curve25519Legacy (RFC 9580 5.5.5.6.1.1), and X25519 and
        /// X448 as ECDH curves, which version 6 keys use with algorithms 25 and 26 instead.
        /// </summary>
        private static bool IsVersion4OnlyEcdhCurve(DerObjectIdentifier curveOid) =>
            CryptlibObjectIdentifiers.curvey25519.Equals(curveOid) ||
            EdECObjectIdentifiers.id_X25519.Equals(curveOid) ||
            EdECObjectIdentifiers.id_X448.Equals(curveOid);

        private static bool IsVersion6OnlyAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
            case PublicKeyAlgorithmTag.MLKem1024_X448:
                return true;
            default:
                return false;
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        [Obsolete("Use constructor with additional 'version' parameter instead")]
        public PublicKeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
            : this(Version4, algorithm, time, key)
        {
        }

        public PublicKeyPacket(byte version, PublicKeyAlgorithmTag algorithm, DateTime time,
            IBcpgKey key)
            : this(PacketTag.PublicKey, version, algorithm, time, key)
        {
        }

        internal PublicKeyPacket(PacketTag keyTag, byte version, PublicKeyAlgorithmTag algorithm, DateTime time,
            IBcpgKey key)
            : base(keyTag, newPacketFormat: version == Version6)
        {
            m_version = version;
            m_time = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            m_algorithm = algorithm;
            m_key = key;
        }

        public virtual int Version => m_version;

        public virtual byte VersionByte => m_version;

        public virtual PublicKeyAlgorithmTag Algorithm => m_algorithm;

        public virtual int ValidDays => m_validDays;

        public virtual DateTime GetTime() => DateTimeUtilities.UnixMsToDateTime(m_time * 1000L);

        public virtual IBcpgKey Key => m_key;

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

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag, GetEncodedContents());

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
