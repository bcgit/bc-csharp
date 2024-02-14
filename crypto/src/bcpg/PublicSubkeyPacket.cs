using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic packet for a PGP public subkey</remarks>
    public class PublicSubkeyPacket
        : PublicKeyPacket
    {
        internal PublicSubkeyPacket(
            BcpgInputStream bcpgIn)
			: base(bcpgIn)
        {
        }

        /// <summary>Construct a public subkey packet.</summary>
        public PublicSubkeyPacket(
            int version,
            PublicKeyAlgorithmTag algorithm,
            DateTime time,
            IBcpgKey key)
            : base(version, algorithm, time, key)
        {
        }

        /// <summary>Construct a version 4 public subkey packet.</summary>
        public PublicSubkeyPacket(
            PublicKeyAlgorithmTag	algorithm,
            DateTime				time,
            IBcpgKey				key)
            : base(DefaultVersion, algorithm, time, key)
        {
        }

		public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.PublicSubkey, GetEncodedContents());
        }
    }
}
