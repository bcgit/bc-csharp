using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public subkey</remarks>
    public class PublicSubkeyPacket
        : PublicKeyPacket
    {
        internal PublicSubkeyPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal PublicSubkeyPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.PublicSubkey, bcpgIn, newPacketFormat)
        {
        }

        /// <summary>Construct a version 4 public subkey packet.</summary>
        [Obsolete("Use constructor with additional 'version' parameter instead")]
        public PublicSubkeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
            : this(Version4, algorithm, time, key)
        {
        }

        /// <summary>Create a new <see cref="PublicSubkeyPacket"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="time">The time.</param>
        /// <param name="key">The key.</param>
        public PublicSubkeyPacket(byte version, PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
            : base(PacketTag.PublicSubkey, version, algorithm, time, key)
        {
        }

        /// <inheritdoc/>
        // TODO[api] Remove this redundant override
        public override void Encode(BcpgOutputStream bcpgOut) => base.Encode(bcpgOut);
    }
}
