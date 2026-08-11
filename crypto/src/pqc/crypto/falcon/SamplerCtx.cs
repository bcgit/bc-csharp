namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal class SamplerCtx
    {
        internal readonly FalconRng p = new FalconRng();
        internal readonly FalconFPR sigma_min;

        internal SamplerCtx(FalconFPR sigma_min)
        {
            this.sigma_min = sigma_min;
        }
    }
}
