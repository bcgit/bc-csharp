namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    internal sealed class PointProj
    {
        internal PointProj(uint nwords_field)
        {
            X = SikeUtilities.InitArray(2, nwords_field);
            Z = SikeUtilities.InitArray(2, nwords_field);
        }
        internal ulong[][] X;
        internal ulong[][] Z;
    }
}
