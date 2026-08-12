namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal class SamplerCtx
    {
        internal readonly FalconRng p = new FalconRng();
        internal readonly FalconFpr sigma_min;

        internal SamplerCtx(FalconFpr sigma_min)
        {
            this.sigma_min = sigma_min;
        }
    }
}
