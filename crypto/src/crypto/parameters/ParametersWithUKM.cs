using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ParametersWithUKM : ICipherParameters
    {
        private readonly byte[] ukm;
        private readonly ICipherParameters parameters;

        public ParametersWithUKM(
            ICipherParameters parameters,
            byte[] ukm) : this(parameters, ukm, 0, ukm.Length)
        {

        }

        public ParametersWithUKM(
            ICipherParameters parameters,
            byte[] ukm,
            int ukmOff,
            int ukmLen)
        {
            this.ukm = new byte[ukmLen];
            this.parameters = parameters;

            Array.Copy(ukm, ukmOff, this.ukm, 0, ukmLen);
        }

        public byte[] GetUKM()
        {
            return this.ukm;
        }

        public ICipherParameters GetParameters()
        {
            return this.parameters;
        }
    }
}
