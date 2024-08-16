using Org.BouncyCastle.Utilities;
using System;
using System.Data.SqlTypes;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a symmetric encrypted session key packet
    */
    public class SymmetricKeyEncSessionPacket
        : ContainedPacket
    {
        /// <summary>
        /// Version 4 SKESK packet.
        /// Used only with V1 SEIPD or SED packets.
        /// </summary>
        public const int Version4 = 4;

        /// <summary>
        /// Version 5 SKESK packet.
        /// Used only with AEADEncDataPacket AED packets.
        /// Defined in retired "RFC4880-bis" draft
        /// </summary>
        /// <seealso href="https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-symmetric-key-encrypted-ses"/>
        public const int Version5 = 5;

        /// <summary>
        /// Version 6 SKESK packet.
        /// Used only with V2 SEIPD packets.
        /// </summary>
        public const int Version6 = 6;

        private readonly int version;
        private readonly SymmetricKeyAlgorithmTag encAlgorithm;
        private readonly S2k s2k;
        private readonly byte[] secKeyData;

        private readonly byte[] s2kBytes;
        private readonly AeadAlgorithmTag aeadAlgorithm;
        private readonly byte[] iv;

        public SymmetricKeyEncSessionPacket(
            BcpgInputStream bcpgIn)
            :base(PacketTag.SymmetricKeyEncryptedSessionKey)
        {
            version = bcpgIn.ReadByte();

            switch (version)
            {
                case Version4:
                    encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();
                    s2k = new S2k(bcpgIn);
                    secKeyData = bcpgIn.ReadAll();
                    break;

                case Version5:
                case Version6:
                    // https://www.rfc-editor.org/rfc/rfc9580#name-version-6-symmetric-key-enc
                    // SymmAlgo + AEADAlgo + S2KCount + S2K + IV
                    int next5Fields5Count = bcpgIn.ReadByte();
                    encAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();
                    aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.ReadByte();

                    int s2kOctetCount = bcpgIn.ReadByte();
                    s2kBytes = new byte[s2kOctetCount];
                    bcpgIn.ReadFully(s2kBytes);
                    s2k = new S2k(new MemoryStream(s2kBytes));

                    int ivsize = AeadUtils.GetIVLength(aeadAlgorithm);
                    iv = new byte[ivsize];
                    bcpgIn.ReadFully(iv);

                    // contains both the encrypted session key and the AEAD authentication tag
                    secKeyData = bcpgIn.ReadAll();
                    break;
            }
        }

        /// <summary>
        /// Create a v4 SKESK packet.
        /// </summary>
        /// <param name="encAlgorithm">symmetric encryption algorithm</param>
        /// <param name="s2k">s2k specifier</param>
        /// <param name="secKeyData">encrypted session key</param>
        public SymmetricKeyEncSessionPacket(
            SymmetricKeyAlgorithmTag    encAlgorithm,
            S2k							s2k,
            byte[]						secKeyData)
            : base(PacketTag.SymmetricKeyEncryptedSessionKey)
        {
            this.version = Version4;
            this.encAlgorithm = encAlgorithm;
            this.s2k = s2k;
            this.secKeyData = secKeyData;
        }


        /// <summary>
        /// Create a v6 SKESK packet.
        /// </summary>
        /// <param name="encAlgorithm"></param>
        /// <param name="aeadAlgorithm"></param>
        /// <param name="iv"></param>
        /// <param name="s2k"></param>
        /// <param name="secKeyData"></param>
        /// <exception cref="IllegalArgumentException"></exception>
        public SymmetricKeyEncSessionPacket(
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            byte[] iv,
            S2k s2k,
            byte[] secKeyData)
            : base(PacketTag.SymmetricKeyEncryptedSessionKey)
        {
            this.version = Version6;
            this.encAlgorithm = encAlgorithm;
            this.aeadAlgorithm = aeadAlgorithm;
            this.s2k = s2k;
            this.secKeyData = Arrays.Clone(secKeyData);

            int expectedIVLen = AeadUtils.GetIVLength(aeadAlgorithm);
            if (expectedIVLen != iv.Length)
            {
                throw new ArgumentException($"Mismatched AEAD IV length. Expected {expectedIVLen}, got {iv.Length}");
            }

            this.iv = Arrays.Clone(iv);
        }

        /**
        * @return int
        */
        public SymmetricKeyAlgorithmTag EncAlgorithm
        {
			get { return encAlgorithm; }
        }

        public AeadAlgorithmTag AeadAlgorithm
        {
            get { return aeadAlgorithm; }
        }

        /**
        * @return S2k
        */
        public S2k S2k
        {
			get { return s2k; }
        }

        /**
        * @return byte[]
        */
        public byte[] GetSecKeyData()
        {
            return secKeyData;
        }

        /**
        * @return int
        */
        public int Version
        {
			get { return version; }
        }

        internal byte[] GetAAData()
        {
            return CreateAAData(Version, EncAlgorithm, AeadAlgorithm);
        }

        internal static byte[] CreateAAData(int version, SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm)
        {
            return new byte[]
            {
                0xC0 | (byte)PacketTag.SymmetricKeyEncryptedSessionKey,
                (byte)version,
                (byte)encAlgorithm,
                (byte)aeadAlgorithm
            };
        }

        internal byte[] GetAeadIV()
        {
            return Arrays.Clone(iv);
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {
                    pOut.WriteByte((byte)version);

                    if (version == Version4)
                    {
                        pOut.WriteByte((byte)encAlgorithm);
                        pOut.WriteObject(s2k);

                        if (secKeyData != null && secKeyData.Length > 0)
                        {
                            pOut.Write(secKeyData);
                        }
                    }
                    else if (version == Version5 || version == Version6)
                    {
                        var s2kenc = s2k.GetEncoded();
                        int s2kLen = s2kenc.Length;

                        // len of 5 following fields
                        int count = 1 + 1 + 1 + s2kLen + iv.Length;
                        pOut.WriteByte((byte)count);

                        pOut.WriteByte((byte)encAlgorithm);
                        pOut.WriteByte((byte)aeadAlgorithm);
                        pOut.WriteByte((byte)s2kLen);
                        pOut.Write(s2kenc);
                        pOut.Write(iv);

                        if (secKeyData != null && secKeyData.Length > 0)
                        {
                            pOut.Write(secKeyData);
                        }
                    }
                }

                bcpgOut.WritePacket(PacketTag.SymmetricKeyEncryptedSessionKey, bOut.ToArray());
            }
        }
    }
}
