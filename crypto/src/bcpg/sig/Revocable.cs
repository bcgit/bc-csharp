namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * packet giving whether or not is revocable.
     */
    public class Revocable
        : SignatureSubpacket
    {
        public Revocable(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength, data)
        {
        }

        public Revocable(bool critical, bool isRevocable)
            : base(SignatureSubpacketTag.Revocable, critical, isLongLength: false,
                Utilities.BooleanToBytes(isRevocable))
        {
        }

        public bool IsRevocable() => Utilities.BooleanFromBytes(data);
    }
}
