using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class InputStreamTest
        : SimpleTest
    {
        private static readonly byte[] outOfBoundsLength = new byte[] { (byte)0x30, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff };
        private static readonly byte[] negativeLength = new byte[] { (byte)0x30, (byte)0x84, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff };
        private static readonly byte[] outsideLimitLength = new byte[] { (byte)0x30, (byte)0x83, (byte)0x0f, (byte)0xff, (byte)0xff };

        private static readonly byte[] classCast1 = Base64.Decode("p1AkHmYAvfOEIrL4ESfrNg==");
        private static readonly byte[] classCast2 = Base64.Decode("JICNbaBUTTq7uxj5mg==");
        private static readonly byte[] classCast3 = Base64.Decode("JAKzADNCxhrrBSVS");
        private static readonly byte[] memoryError1 = Base64.Decode("vm66gOiEe+FV/NvujMwSkUp5Lffw5caQlaRU5sdMPC70IGWmyK2/");
        private static readonly byte[] memoryError2 = Base64.Decode("vm4ogOSEfVGsS3w+KTzb2A0ALYR8VBOQqQeuRwnsPC4AAGWEDLjd");

        public override string Name
        {
            get { return "InputStream"; }
        }

        public override void PerformTest()
        {
            Asn1InputStream aIn = new Asn1InputStream(outOfBoundsLength);

            try
            {
                aIn.ReadObject();
                Fail("out of bounds length not detected.");
            }
            catch (IOException e)
            {
                if (!e.Message.Equals("invalid long form definite-length 0xFF"))
                {
                    Fail("wrong exception: " + e.Message);
                }
            }

            // NOTE: Not really a "negative" length, but 32 bits
            aIn = new Asn1InputStream(negativeLength);

            try
            {
                aIn.ReadObject();
                Fail("negative length not detected.");
            }
            catch (IOException e)
            {
                if (!e.Message.Equals("long form definite-length more than 31 bits"))
                {
                    Fail("wrong exception: " + e.Message);
                }
            }

            aIn = new Asn1InputStream(outsideLimitLength);

            try
            {
                aIn.ReadObject();
                Fail("outside limit length not detected.");
            }
            catch (IOException e)
            {
                if (!e.Message.Equals("corrupted stream - out of bounds length found: 1048575 >= 5"))
                {
                    Fail("wrong exception: " + e.Message);
                }
            }

            // TODO Test data has length issues too; needs to be reworked
            //DoTestWithByteArray(classCast1, "unknown object encountered: Org.BouncyCastle.Asn1.DerApplicationSpecific");
            DoTestWithByteArray(classCast2, "unknown object encountered: Org.BouncyCastle.Asn1.DLTaggedObjectParser");
            DoTestWithByteArray(classCast3, "unknown object encountered in constructed OCTET STRING: Org.BouncyCastle.Asn1.DLTaggedObject");

            // TODO Error dependent on parser choices; needs to be reworked
            //DoTestWithByteArray(memoryError1, "corrupted stream - out of bounds length found: 2078365180 >= 39");
            //DoTestWithByteArray(memoryError2, "corrupted stream - out of bounds length found: 2102504523 >= 39");
        }

        private void DoTestWithByteArray(byte[] data, string message)
        {
            try
            {
                Asn1InputStream input = new Asn1InputStream(data);

                IAsn1Convertible p;
                while ((p = input.ReadObject()) != null)
                {
                    Asn1Sequence asn1 = Asn1Sequence.GetInstance(p);
                    for (int i = 0; i < asn1.Count; i++)
                    {
                        IAsn1Convertible c = asn1[i];
                    }
                }
            }
            catch (IOException e)
            {
                IsEquals(e.Message, message, e.Message);
            }
            // TODO Without InMemoryRepresentable, the IOException may be swapped/wrapped with an Asn1ParsingException
            catch (Asn1ParsingException e)
            {
                Exception messageException = e;

                IOException ioe = e.InnerException as IOException;
                if (ioe != null)
                {
                    messageException = ioe;
                }

                IsEquals(messageException.Message, message, messageException.Message);
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
