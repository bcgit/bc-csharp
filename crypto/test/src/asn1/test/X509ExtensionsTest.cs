using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class X509ExtensionsTest
        : SimpleTest
    {
        private static readonly DerObjectIdentifier Oid1 = new DerObjectIdentifier("1.2.1");
        private static readonly DerObjectIdentifier Oid2 = new DerObjectIdentifier("1.2.2");
        private static readonly DerObjectIdentifier Oid3 = new DerObjectIdentifier("1.2.3");

        public override string Name
        {
            get { return "X509Extensions"; }
        }


        [Test]
        public void TestDuplicateExtensions()
        {

            // Testing for handling of duplicates

            GeneralName name1 = new GeneralName(GeneralName.DnsName, "bc1.local");
            GeneralName name2 = new GeneralName(GeneralName.DnsName, "bc2.local");


            X509ExtensionsGenerator extensionsGenerator = new X509ExtensionsGenerator();
            extensionsGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name1 })));
            extensionsGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name2 })));

            //
            // Generate and deserialise.
            //
            X509Extensions ext = X509Extensions.GetInstance(Asn1Sequence.GetInstance(extensionsGenerator.Generate().GetEncoded()));
            X509Extension returnedExtension = ext.GetExtension(X509Extensions.SubjectAlternativeName);
            Asn1Sequence seq = Asn1Sequence.GetInstance(returnedExtension.GetParsedValue());


            //
            // Check expected order and value.
            //
            if (!GeneralName.GetInstance(seq[0]).Equals(name1))
            {
                Fail("expected name 1");
            }

            if (!GeneralName.GetInstance(seq[1]).Equals(name2))
            {
                Fail("expected name 2");
            }


            //
            // Test we can load dup extensions into a new generator
            //

            X509ExtensionsGenerator genX = new X509ExtensionsGenerator();
            genX.AddExtensions(ext);

            ext = X509Extensions.GetInstance(Asn1Sequence.GetInstance(genX.Generate().GetEncoded()));
            returnedExtension = ext.GetExtension(X509Extensions.SubjectAlternativeName);
            seq = Asn1Sequence.GetInstance(returnedExtension.GetParsedValue());



            //
            // Check expected order and value.
            //
            if (!GeneralName.GetInstance(seq[0]).Equals(name1))
            {
                Fail("expected name 1");
            }

            if (!GeneralName.GetInstance(seq[1]).Equals(name2))
            {
                Fail("expected name 2");
            }




        }


        [Test]
        public void TestAllowedDuplicateExtensions()
        {

            // Testing for handling of duplicates

            GeneralName name1 = new GeneralName(GeneralName.DnsName, "bc1.local");
            GeneralName name2 = new GeneralName(GeneralName.DnsName, "bc2.local");


            X509ExtensionsGenerator extensionsGenerator = new X509ExtensionsGenerator();
            extensionsGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name1 })));
            extensionsGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name2 })));

            extensionsGenerator.AddExtension(X509Extensions.IssuerAlternativeName, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name1 })));
            extensionsGenerator.AddExtension(X509Extensions.IssuerAlternativeName, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name2 })));


            extensionsGenerator.AddExtension(X509Extensions.SubjectDirectoryAttributes, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name1 })));
            extensionsGenerator.AddExtension(X509Extensions.SubjectDirectoryAttributes, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name2 })));

            extensionsGenerator.AddExtension(X509Extensions.CertificateIssuer, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name1 })));
            extensionsGenerator.AddExtension(X509Extensions.CertificateIssuer, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name2 })));


            extensionsGenerator.AddExtension(X509Extensions.AuditIdentity, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name1 })));
            try
            {
                extensionsGenerator.AddExtension(X509Extensions.AuditIdentity, false, new DerSequence(new Asn1EncodableVector(new Asn1Encodable[] { name2 })));
                Fail("Expected exception, not a white listed duplicate.");
            }
            catch (Exception)
            {
                // ok
            }

        }


        public override void PerformTest()
        {
            X509ExtensionsGenerator gen = new X509ExtensionsGenerator();

            gen.AddExtension(Oid1, true, new byte[20]);
            gen.AddExtension(Oid2, true, new byte[20]);

            X509Extensions ext1 = gen.Generate();
            X509Extensions ext2 = gen.Generate();

            if (!ext1.Equals(ext2))
            {
                Fail("Equals test failed");
            }

            gen.Reset();

            gen.AddExtension(Oid2, true, new byte[20]);
            gen.AddExtension(Oid1, true, new byte[20]);

            ext2 = gen.Generate();

            if (ext1.Equals(ext2))
            {
                Fail("inequality test failed");
            }

            if (!ext1.Equivalent(ext2))
            {
                Fail("equivalence true failed");
            }

            gen.Reset();

            gen.AddExtension(Oid1, true, new byte[22]);
            gen.AddExtension(Oid2, true, new byte[20]);

            ext2 = gen.Generate();

            if (ext1.Equals(ext2))
            {
                Fail("inequality 1 failed");
            }

            if (ext1.Equivalent(ext2))
            {
                Fail("non-equivalence 1 failed");
            }

            gen.Reset();

            gen.AddExtension(Oid3, true, new byte[20]);
            gen.AddExtension(Oid2, true, new byte[20]);

            ext2 = gen.Generate();

            if (ext1.Equals(ext2))
            {
                Fail("inequality 2 failed");
            }

            if (ext1.Equivalent(ext2))
            {
                Fail("non-equivalence 2 failed");
            }

            try
            {
                gen.AddExtension(Oid2, true, new byte[20]);
                Fail("repeated oid");
            }
            catch (ArgumentException e)
            {
                if (!e.Message.Equals("extension 1.2.2 already added"))
                {
                    Fail("wrong exception on repeated oid: " + e.Message);
                }
            }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new X509ExtensionsTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
