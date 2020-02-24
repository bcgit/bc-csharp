using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class BerOctetString
        : DerOctetString, IEnumerable
    {
        private static readonly int DefaultChunkSize = 1000;

        public static BerOctetString FromSequence(Asn1Sequence seq)
        {
            int count = seq.Count;
            Asn1OctetString[] v = new Asn1OctetString[count];
            for (int i = 0; i < count; ++i)
            {
                v[i] = Asn1OctetString.GetInstance(seq[i]);
            }
            return new BerOctetString(v);
        }

        private static byte[] ToBytes(Asn1OctetString[] octs)
        {
            MemoryStream bOut = new MemoryStream();
            foreach (Asn1OctetString o in octs)
            {
                byte[] octets = o.GetOctets();
                bOut.Write(octets, 0, octets.Length);
            }
            return bOut.ToArray();
        }

        private static Asn1OctetString[] ToOctetStringArray(IEnumerable e)
        {
            IList list = Platform.CreateArrayList(e);

            int count = list.Count;
            Asn1OctetString[] v = new Asn1OctetString[count];
            for (int i = 0; i < count; ++i)
            {
                v[i] = Asn1OctetString.GetInstance(list[i]);
            }
            return v;
        }

        private readonly int chunkSize;
        private readonly Asn1OctetString[] octs;

        [Obsolete("Will be removed")]
        public BerOctetString(IEnumerable e)
            : this(ToOctetStringArray(e))
        {
        }

        public BerOctetString(byte[] str)
			: this(str, DefaultChunkSize)
		{
		}

        public BerOctetString(Asn1OctetString[] octs)
            : this(octs, DefaultChunkSize)
        {
        }

        public BerOctetString(byte[] str, int chunkSize)
            : this(str, null, chunkSize)
        {
        }

        public BerOctetString(Asn1OctetString[] octs, int chunkSize)
            : this(ToBytes(octs), octs, chunkSize)
        {
        }

        private BerOctetString(byte[] str, Asn1OctetString[] octs, int chunkSize)
            : base(str)
        {
            this.octs = octs;
            this.chunkSize = chunkSize;
        }

        /**
         * return the DER octets that make up this string.
         */
		public IEnumerator GetEnumerator()
		{
			if (octs == null)
			{
				return GenerateOcts().GetEnumerator();
			}

			return octs.GetEnumerator();
		}

		[Obsolete("Use GetEnumerator() instead")]
        public IEnumerator GetObjects()
        {
			return GetEnumerator();
		}

		private IList GenerateOcts()
        {
            IList vec = Platform.CreateArrayList();
            for (int i = 0; i < str.Length; i += chunkSize)
            { 
				int end = System.Math.Min(str.Length, i + chunkSize);

                byte[] nStr = new byte[end - i]; 

                Array.Copy(str, i, nStr, 0, nStr.Length);

                vec.Add(new DerOctetString(nStr));
             } 
             return vec; 
        }

        internal override void Encode(
            DerOutputStream derOut)
        {
            if (derOut is Asn1OutputStream || derOut is BerOutputStream)
            {
                derOut.WriteByte(Asn1Tags.Constructed | Asn1Tags.OctetString);

                derOut.WriteByte(0x80);

                //
                // write out the octet array
                //
                foreach (Asn1OctetString oct in this)
                {
                    derOut.WriteObject(oct);
                }

				derOut.WriteByte(0x00);
                derOut.WriteByte(0x00);
            }
            else
            {
                base.Encode(derOut);
            }
        }
    }
}
