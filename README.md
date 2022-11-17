# The Bouncy Castle Cryptography Library For .NET
[![NuGet](https://img.shields.io/nuget/dt/BouncyCastle.Cryptography.svg)](https://www.nuget.org/packages/BouncyCastle.Cryptography) [![NuGet](https://img.shields.io/nuget/vpre/BouncyCastle.Cryptography.svg)](https://www.nuget.org/packages/BouncyCastle.Cryptography)

The Bouncy Castle Cryptography library is a .NET implementation of cryptographic algorithms and protocols. It was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

In addition to providing basic cryptography algorithms, the package also provides support for CMS, OpenPGP, (D)TLS, TSP, X.509 certificate generation and more. The package also includes implementations of the following NIST Post-Quantum Cryptography Standardization algorithms: CRYSTALS-Dilithium, CRYSTALS-Kyber, Falcon, SPHINCS+, Classic McEliece, FrodoKEM, NTRU, NTRU Prime, Picnic, Saber, BIKE, and SIKE. These should all be considered EXPERIMENTAL and subject to change or removal. SIKE in particular is already slated for removal and should be used for research purposes only.

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/csharp/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a [support contract](https://www.keyfactor.com/platform/bouncy-castle-support/).

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). This software includes a modified Bzip2 library, which is licensed under the [Apache Software License, Version 2.0](http://www.apache.org/licenses/). 

**Note**: This source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please visit us [here](https://www.bouncycastle.org/fips-csharp) or contact us directly at [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Installing BouncyCastle
You should install [BouncyCastle with NuGet:](https://www.nuget.org/packages/BouncyCastle.Cryptography)

    Install-Package BouncyCastle.Cryptography

Or via the .NET Core command line interface:

    dotnet add package BouncyCastle.Cryptography

Either commands, from Package Manager Console or .NET Core CLI, will download and install BouncyCastle.Cryptography.


## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-csharp-request@bouncycastle.org](mailto:announce-crypto-csharp-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-csharp-request@bouncycastle.org](mailto:dev-crypto-csharp-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback 

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org). If you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues on [github](https://github.com/bcgit/bc-csharp), or via [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org) if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
