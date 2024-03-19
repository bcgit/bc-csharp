namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving whether or not the signature is signed using the primary user ID for the key.
    */
    public class PrimaryUserId
        : SignatureSubpacket
    {
        public PrimaryUserId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, isLongLength, data)
        {
        }

        public PrimaryUserId(bool critical, bool isPrimaryUserId)
            : base(SignatureSubpacketTag.PrimaryUserId, critical, false, Utilities.BooleanToBytes(isPrimaryUserId))
        {
        }

        public bool IsPrimaryUserId() => Utilities.BooleanFromBytes(data);
    }
}
