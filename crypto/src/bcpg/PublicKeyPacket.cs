using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        public const int Version2 = 2;
        public const int Version3 = 3;
        public const int Version4 = 4;
        public const int Version5 = 5;
        public const int Version6 = 6;

        private readonly int version;
        private readonly long time;
        private readonly int validDays;
        private readonly PublicKeyAlgorithmTag algorithm;
        private readonly IBcpgKey key;

        private readonly long v6KeyLen;

        internal PublicKeyPacket(
            BcpgInputStream bcpgIn)
        {
            version = bcpgIn.ReadByte();

            time = ((uint)bcpgIn.ReadByte() << 24) | ((uint)bcpgIn.ReadByte() << 16)
                | ((uint)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte();

            if (version <= Version3)
            {
                validDays = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            }

            algorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();

            if (version == Version5 || version == Version6)
            {
                v6KeyLen = ((uint)bcpgIn.ReadByte() << 24) | ((uint)bcpgIn.ReadByte() << 16)
                    | ((uint)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte();
            }

            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.RsaEncrypt:
            case PublicKeyAlgorithmTag.RsaGeneral:
            case PublicKeyAlgorithmTag.RsaSign:
                key = new RsaPublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.Dsa:
                key = new DsaPublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                key = new ElGamalPublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.ECDH:
                key = new ECDHPublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.ECDsa:
                key = new ECDsaPublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                key = new EdDsaPublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.Ed25519:
                key = new Ed25519PublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.Ed448:
                key = new Ed448PublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.X25519:
                key = new X25519PublicBcpgKey(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.X448:
                key = new X448PublicBcpgKey(bcpgIn);
                break;
            default:
            throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        public PublicKeyPacket(
            PublicKeyAlgorithmTag	algorithm,
            DateTime				time,
            IBcpgKey				key)
        {
            this.version = Version4;
            this.time = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            this.algorithm = algorithm;
            this.key = key;
        }

        public virtual int Version
        {
            get { return version; }
        }

        public virtual PublicKeyAlgorithmTag Algorithm
        {
            get { return algorithm; }
        }

        public virtual int ValidDays
        {
            get { return validDays; }
        }

        public virtual DateTime GetTime()
        {
            return DateTimeUtilities.UnixMsToDateTime(time * 1000L);
        }

        public virtual IBcpgKey Key
        {
            get { return key; }
        }

        public virtual byte[] GetEncodedContents()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte((byte)version);
                pOut.WriteInt((int)time);

                if (version <= Version3)
                {
                    pOut.WriteShort((short)validDays);
                }

                pOut.WriteByte((byte)algorithm);

                if (version == Version5 || version == Version6)
                {
                    pOut.WriteInt((int)v6KeyLen);
                }

                pOut.WriteObject((BcpgObject)key);
            }
            return bOut.ToArray();
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.PublicKey, GetEncodedContents());
        }
    }
}
