using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a symmetric encrypted session key packet.</summary>
    public class SymmetricKeyEncSessionPacket
        : ContainedPacket
    {
        public const byte Version4 = 4;
        public const byte Version5 = 5;
        public const byte Version6 = 6;

        public static SymmetricKeyEncSessionPacket CreateV4Packet(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k,
            byte[] secKeyData)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, secKeyData);
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SymmetricKeyEncSessionPacket CreateV5Packet(SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] iv, S2k s2k, byte[] secKeyData, byte[] authTag)
        {
            return new SymmetricKeyEncSessionPacket(Version5, encAlgorithm, aeadAlgorithm, iv, s2k, secKeyData, authTag);
        }

        public static SymmetricKeyEncSessionPacket CreateV6Packet(SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] iv, S2k s2k, byte[] secKeyData, byte[] authTag)
        {
            return new SymmetricKeyEncSessionPacket(Version6, encAlgorithm, aeadAlgorithm, iv, s2k, secKeyData, authTag);
        }

        private readonly byte m_version;                            // V4, V5, V6
        private readonly SymmetricKeyAlgorithmTag m_encAlgorithm;   // V4, V5, V6
        private readonly AeadAlgorithmTag m_aeadAlgorithm;          // V5, V6
        private readonly S2k m_s2k;                                 // V4, V5, V6
        private readonly byte[] m_secKeyData;                       // V4, V5, V6
        private readonly byte[] m_iv;                               // V5, V6
        private readonly byte[] m_authTag;                          // V5, V6

        public SymmetricKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {
            m_version = bcpgIn.RequireByte();

            switch (m_version)
            {
            case Version4:
            {
                m_encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
                m_aeadAlgorithm = 0;
                m_s2k = new S2k(bcpgIn);
                m_secKeyData = bcpgIn.ReadAll();
                m_iv = null;
                m_authTag = null;
                break;
            }
            case Version5:
            case Version6:
            {
                int ivLen = 0;
                if (m_version == Version6)
                {
                    // https://www.rfc-editor.org/rfc/rfc9580.html#section-5.3.2-3.2.1
                    // SymAlg + AEADAlg + S2KCount + S2K + IV
                    ivLen = bcpgIn.RequireByte(); // next5Fields5Count
                }

                m_encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
                m_aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.RequireByte();

                if (m_version == Version6)
                {
                    // https://www.rfc-editor.org/rfc/rfc9580.html#section-5.3.2-3.5.1
                    int s2kOctetCount = bcpgIn.RequireByte();
                    ivLen = ivLen - 3 - s2kOctetCount;
                }
                else
                {
                    try
                    {
                        ivLen = AeadUtilities.GetIVLength(m_aeadAlgorithm);
                    }
                    catch (ArgumentException e)
                    {
                        throw new MalformedPacketException("Unknown AEAD algorithm.", e);
                    }
                }

                if (ivLen < 0)
                    throw new MalformedPacketException("IV length cannot be negative.");

                m_s2k = new S2k(bcpgIn);

                m_iv = new byte[ivLen]; // also called nonce
                bcpgIn.ReadFully(m_iv);

                int authTagLen;
                try
                {
                    authTagLen = AeadUtilities.GetAuthTagLength(m_aeadAlgorithm);
                }
                catch (ArgumentException e)
                {
                    throw new MalformedPacketException("Unknown AEAD algorithm.", e);
                }

                // Read all trailing bytes
                byte[] secKeyAndAuthTag = bcpgIn.ReadAll();
                if (secKeyAndAuthTag.Length < authTagLen)
                    throw new MalformedPacketException("AuthTagLen exceeds session key data.");

                // determine session key length by subtracting auth tag
                int secKeyLen = secKeyAndAuthTag.Length - authTagLen;

                m_secKeyData = Arrays.CopySegment(secKeyAndAuthTag, 0, secKeyLen);
                m_authTag = Arrays.CopySegment(secKeyAndAuthTag, secKeyLen, authTagLen);
                break;
            }
            default:
            {
                throw new UnsupportedPacketVersionException(
                    "Unsupported PGP symmetric-key encrypted session key packet version encountered: " + m_version);
            }
            }
        }

        [Obsolete("Use 'CreateV4Packet' instead")]
        public SymmetricKeyEncSessionPacket(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] secKeyData)
        {
            m_version = Version4;
            m_encAlgorithm = encAlgorithm;
            m_aeadAlgorithm = 0;
            m_s2k = s2k;
            m_secKeyData = secKeyData;
            m_iv = null;
            m_authTag = null;
        }

        /// <remarks>Create a v5 or v6 SKESK packet.</remarks>
        private SymmetricKeyEncSessionPacket(byte version, SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] iv, S2k s2k, byte[] secKeyData, byte[] authTag)
        {
            int expectedIVLen = AeadUtilities.GetIVLength(aeadAlgorithm);
            if (expectedIVLen != iv.Length)
            {
                var msg = $"Mismatched AEAD IV length. Expected {expectedIVLen}, got {iv.Length}";
                throw new ArgumentException(msg, nameof(iv));
            }

            int expectedAuthTagLen = AeadUtilities.GetAuthTagLength(aeadAlgorithm);
            if (expectedAuthTagLen != authTag.Length)
            {
                var msg = $"Mismatched AEAD AuthTag length. Expected {expectedAuthTagLen}, got {authTag.Length}";
                throw new ArgumentException(msg, nameof(authTag));
            }

            m_version = version;
            m_encAlgorithm = encAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_s2k = s2k;
            m_secKeyData = secKeyData;
            m_iv = iv;
            m_authTag = authTag;
        }

        public AeadAlgorithmTag AeadAlgorithm => m_aeadAlgorithm;

        public SymmetricKeyAlgorithmTag EncAlgorithm => m_encAlgorithm;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bool newFormatOnly = m_version > Version4;

            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut, newFormatOnly))
            {
                switch (m_version)
                {
                case Version4:
                {
                    pOut.Write(m_version, (byte)m_encAlgorithm);
                    m_s2k.Encode(pOut);

                    if (m_secKeyData != null && m_secKeyData.Length > 0)
                    {
                        pOut.Write(m_secKeyData);
                    }
                    break;
                }
                case Version5:
                {
                    pOut.Write(m_version, (byte)m_encAlgorithm, (byte)m_aeadAlgorithm);
                    m_s2k.Encode(pOut);
                    pOut.Write(m_iv);

                    if (m_secKeyData != null && m_secKeyData.Length > 0)
                    {
                        pOut.Write(m_secKeyData);
                    }

                    pOut.Write(m_authTag);
                    break;
                }
                case Version6:
                {
                    byte[] s2kEncoded = m_s2k.GetEncoded();
                    int count = 1 + 1 + 1 + s2kEncoded.Length + m_iv.Length; // len of 5 following fields

                    pOut.Write(m_version, (byte)count, (byte)m_encAlgorithm, (byte)m_aeadAlgorithm,
                        (byte)s2kEncoded.Length);
                    pOut.Write(s2kEncoded);
                    pOut.Write(m_iv);

                    if (m_secKeyData != null && m_secKeyData.Length > 0)
                    {
                        pOut.Write(m_secKeyData);
                    }

                    pOut.Write(m_authTag);
                    break;

                }
                default:
                    throw new InvalidOperationException();
                }
            }

            bcpgOut.WritePacket(PacketTag.SymmetricKeyEncryptedSessionKey, bOut.ToArray());
        }

        public byte[] GetAAData() => CreateAAData(VersionByte, EncAlgorithm, AeadAlgorithm);

        public byte[] GetAuthTag() => m_authTag;

        public byte[] GetIV() => m_iv;

        public byte[] GetSecKeyData() => m_secKeyData;

        public S2k S2k => m_s2k;

        public int Version => m_version;

        public byte VersionByte => m_version;

        public static byte[] CreateAAData(byte version, SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm)
        {
            byte[] aaData = new byte[4];
            aaData[0] = (byte)PacketTag.SymmetricKeyEncryptedSessionKey | 0xC0;
            aaData[1] = version;
            aaData[2] = (byte)encAlgorithm;
            aaData[3] = (byte)aeadAlgorithm;
            return aaData;
        }
    }
}
