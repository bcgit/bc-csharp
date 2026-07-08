using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

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
        {
            if (this is SecretSubkeyPacket)
            {
                pubKeyPacket = new PublicSubkeyPacket(bcpgIn);
            }
            else
            {
                pubKeyPacket = new PublicKeyPacket(bcpgIn);
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
        {
            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;

            if (encAlgorithm != SymmetricKeyAlgorithmTag.Null)
            {
                this.s2kUsage = UsageChecksum;
            }
            else
            {
                this.s2kUsage = UsageNone;
            }

            this.s2k = s2k;
            this.iv = Arrays.Clone(iv);
            this.secKeyData = secKeyData;
        }

        public SecretKeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2kUsage,
            S2k s2k, byte[] iv, byte[] secKeyData)
        {
            this.pubKeyPacket = pubKeyPacket;
            this.encAlgorithm = encAlgorithm;
            this.s2kUsage = s2kUsage;
            this.s2k = s2k;
            this.iv = Arrays.Clone(iv);
            this.secKeyData = secKeyData;
        }

        public SymmetricKeyAlgorithmTag EncAlgorithm => encAlgorithm;

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

                if (s2kUsage == UsageChecksum || s2kUsage == UsageSha1)
                {
                    pOut.WriteByte((byte)encAlgorithm);
                    s2k.Encode(pOut);
                }

                if (iv != null)
                {
                    pOut.Write(iv);
                }

                if (secKeyData != null && secKeyData.Length > 0)
                {
                    pOut.Write(secKeyData);
                }
            }
            return bOut.ToArray();
        }

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(PacketTag.SecretKey, GetEncodedContents());
    }
}
