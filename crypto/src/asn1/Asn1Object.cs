using System;
using System.Diagnostics;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Object
		: Asn1Encodable
    {
        public override void EncodeTo(Stream output)
        {
            using (var asn1Out = Asn1OutputStream.Create(output, Ber, leaveOpen: true))
            {
                GetEncoding(asn1Out.Encoding).Encode(asn1Out);
            }
        }

        public override void EncodeTo(Stream output, string encoding)
        {
            using (var asn1Out = Asn1OutputStream.Create(output, encoding, leaveOpen: true))
            {
                GetEncoding(asn1Out.Encoding).Encode(asn1Out);
            }
        }

        internal override byte[] GetEncoded(string encoding, int preAlloc, int postAlloc)
        {
            var encodingType = Asn1OutputStream.GetEncodingType(encoding);
            var asn1Encoding = GetEncoding(encodingType);
            var length = asn1Encoding.GetLength();
            var result = new byte[preAlloc + length + postAlloc];
            using (var asn1Out = Asn1OutputStream.Create(result, preAlloc, length, encoding, leaveOpen: false))
            {
                asn1Encoding.Encode(asn1Out);
                Debug.Assert(asn1Out.Length == asn1Out.Position);
            }
            return result;
        }

        public bool Equals(Asn1Object other)
        {
            return this == other || Asn1Equals(other);
        }

        /// <summary>Create a base ASN.1 object from a byte array.</summary>
        /// <param name="data">The byte array to parse.</param>
        /// <returns>The base ASN.1 object represented by the byte array.</returns>
        /// <exception cref="IOException">
        /// If there is a problem parsing the data, or parsing an object did not exhaust the available data.
        /// </exception>
        public static Asn1Object FromByteArray(byte[] data)
		{
            int limit = data.Length;
            using (var asn1In = new Asn1InputStream(new MemoryStream(data, false), limit))
            {
                Asn1Object result = asn1In.ReadObject();
                if (asn1In.Position != limit)
                    throw new IOException("extra data found after object");
                return result;
            }
		}

        internal static Asn1Object FromMemoryStream(MemoryStream memoryStream)
        {
            int limit = Convert.ToInt32(memoryStream.Length);
            using (var asn1In = new Asn1InputStream(memoryStream, limit))
            {
                Asn1Object result = asn1In.ReadObject();
                if (asn1In.Position != limit)
                    throw new IOException("extra data found after object");
                return result;
            }
        }

        /// <summary>Read a base ASN.1 object from a stream.</summary>
        /// <param name="inStr">The stream to parse.</param>
        /// <returns>The base ASN.1 object represented by the byte array.</returns>
        /// <exception cref="IOException">If there is a problem parsing the data.</exception>
        public static Asn1Object FromStream(Stream inStr)
		{
            using (var asn1In = new Asn1InputStream(inStr, int.MaxValue, leaveOpen: true))
            {
                return asn1In.ReadObject();
            }
		}

        public sealed override Asn1Object ToAsn1Object() => this;

        internal abstract IAsn1Encoding GetEncoding(int encoding);

        internal abstract IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo);

        internal abstract DerEncoding GetEncodingDer();

        internal abstract DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo);

        protected abstract bool Asn1Equals(Asn1Object asn1Object);
		protected abstract int Asn1GetHashCode();

		internal bool CallAsn1Equals(Asn1Object obj)
		{
			return Asn1Equals(obj);
		}

		internal int CallAsn1GetHashCode()
		{
			return Asn1GetHashCode();
		}
	}
}
