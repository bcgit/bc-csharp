namespace Org.BouncyCastle.Crypto.Parameters
{
	public class ParametersWithSBox
		: ICipherParameters
	{
		private readonly ICipherParameters m_parameters;
		private readonly byte[] m_sBox;

		public ParametersWithSBox(ICipherParameters parameters, byte[] sBox)
		{
			this.m_parameters = parameters;
			this.m_sBox = sBox;
		}

		public byte[] GetSBox() => m_sBox;

		public ICipherParameters Parameters => m_parameters;
	}
}
