using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private int version;
        private long time;
        private int validDays;
        private PublicKeyAlgorithmTag algorithm;
        private IBcpgKey key;

        internal PublicKeyPacket(
            BcpgInputStream bcpgIn)
        {
            version = bcpgIn.RequireByte();

            time = StreamUtilities.RequireUInt32BE(bcpgIn);

            if (version <= 3)
            {
                validDays = StreamUtilities.RequireUInt16BE(bcpgIn);
            }

            algorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();

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
            default:
                throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        /// <summary>Construct a version 4 public key packet.</summary>
        public PublicKeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
        {
            this.version = 4;
            this.time = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            this.algorithm = algorithm;
            this.key = key;
        }

        public virtual int Version => version;

        public virtual PublicKeyAlgorithmTag Algorithm => algorithm;

        public virtual int ValidDays => validDays;

        public virtual DateTime GetTime() => DateTimeUtilities.UnixMsToDateTime(time * 1000L);

        public virtual IBcpgKey Key => key;

        public virtual byte[] GetEncodedContents()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte((byte)version);
                pOut.WriteInt((int)time);

                if (version <= 3)
                {
                    pOut.WriteShort((short)validDays);
                }

                pOut.WriteByte((byte)algorithm);
                pOut.WriteObject((BcpgObject)key);
            }
            return bOut.ToArray();
        }

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(PacketTag.PublicKey, GetEncodedContents());
    }
}
