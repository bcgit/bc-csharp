namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    internal sealed class PointProjFull
    {
        internal PointProjFull(uint nwords_field)
        {
            X = SikeUtilities.InitArray(2, nwords_field);
            Y = SikeUtilities.InitArray(2, nwords_field);
            Z = SikeUtilities.InitArray(2, nwords_field);
        }
        internal ulong[][] X;
        internal ulong[][] Y;
        internal ulong[][] Z;
    }
}
