using RSA_Algorithm;

var (publicKey, privateKey) = RSA.GenerateKeypair(64);

Console.WriteLine($"Public key: ({publicKey.e}, {publicKey.n})");
Console.WriteLine($"Private key: ({privateKey.d}, {privateKey.n})");

var messageToCipher = "Hello, World!";

var cipherMessage = RSA.Encrypt(publicKey, messageToCipher);
Console.WriteLine(cipherMessage);

var plainMessage = RSA.Decrypt(privateKey, cipherMessage);
Console.WriteLine(plainMessage);
