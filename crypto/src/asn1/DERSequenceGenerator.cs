using System.IO;

namespace Org.BouncyCastle.Asn1
{
	public class DerSequenceGenerator
		: DerGenerator
	{
		private readonly MemoryStream _bOut = new MemoryStream();

		public DerSequenceGenerator(
			Stream outStream)
			: base(outStream)
		{
		}

		public DerSequenceGenerator(
			Stream	outStream,
			int		tagNo,
			bool	isExplicit)
			: base(outStream, tagNo, isExplicit)
		{
		}

		public override void AddObject(
			Asn1Encodable obj)
		{
            Asn1OutputStream.Create(_bOut, Asn1Encodable.Der).WriteObject(obj);
		}

        public override void AddObject(
            Asn1Object obj)
        {
            Asn1OutputStream.Create(_bOut, Asn1Encodable.Der).WriteObject(obj);
        }

        public override Stream GetRawOutputStream()
		{
			return _bOut;
		}

		public override void Close()
		{
			WriteDerEncoded(Asn1Tags.Constructed | Asn1Tags.Sequence, _bOut.ToArray());
		}
	}
}
