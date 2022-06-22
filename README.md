# Nethereum SIWE Template

The Nethereum SIWE template provides an starting point of signing and authentication using Ethereum accounts and the standard SIWE message.
The templates provides the following use cases, and how SIWE can be implemented using the Nethereum libraries.
+ Rest Api 
+ Blazor Wasm + Rest Api
+ Blazor Server side (standalone)
+ Maui (Future template with Rest Api)
+ Avalonia (Future template with Rest Api)

## SIWE Message, signing and recovery (Overall process)

A SIWE Message is a standard message that a user signs with their private key, the message is presented in plain text to the user. The message contains different attributes including the Domain, Address, Uri, Expiry etc. The issuer of the message can authenticate the signer (user), by matching the recovered address from the signed message to their user records. To prevent replay attacks a unique nonce (random value) is created for each session.

More information can be found here https://eips.ethereum.org/EIPS/eip-4361

```csharp
public class SiweMessage
    {
        /// <summary>
        /// RFC 4501 dns authority that is requesting the signing.
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// Ethereum address performing the signing conformant to capitalization
        /// encoded checksum specified in EIP-55 where applicable.
        /// </summary>
        public string Address { get; set; }

        /// <summary>
        /// Human-readable ASCII assertion that the user will sign, and it must not contain `\n`. 
        /// </summary>
        public string Statement { get; set; }

        /// <summary>
        /// RFC 3986 URI referring to the resource that is the subject of the signing
        /// (as in the __subject__ of a claim).
        /// </summary>
        public string Uri { get; set; }

        /// <summary>
        /// Current version of the message. 
        /// </summary>
        public string Version { get; set; }

        /// <summary>
        /// Randomized token used to prevent replay attacks, at least 8 alphanumeric characters. 
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        ///  ISO 8601 datetime string of the current time. 
        /// </summary>
        public string IssuedAt { get; set; }

        /// <summary>
        /// ISO 8601 datetime string that, if present, indicates when the signed authentication message is no longer valid. 
        /// </summary>
        public string ExpirationTime { get; set; }

        /// <summary>
        /// ISO 8601 datetime string that, if present, indicates when the signed authentication message will become valid. 
        /// </summary>
        public string NotBefore { get; set; }

        /// <summary>
        /// System-specific identifier that may be used to uniquely refer to the sign-in request
        /// </summary>
      
        public string RequestId { get; set; }

        /// <summary>
        /// EIP-155 Chain ID to which the session is bound, and the network where, Contract Accounts must be resolved
        /// </summary>
        public string ChainId { get; set; }

        /// <summary>
        /// List of information or references to information the user wishes to have resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by `\n- `
        /// </summary>
        public List<string> Resources { get; set; }

```

## Rest Api 
The Rest Api sample template demonstrates the following:

### Generate a new Siwe message with a random Nonce

To generate a new siwe message a DefaultSiweMessage class is in place, here you can put your website, statement, expiry, etc
The message is created using the Nethereum SiweMessageService that has been configured with the default [InMemorySessionNonceStorage](https://github.com/Nethereum/Nethereum/blob/master/src/Nethereum.Siwe/InMemorySessionNonceStorage.cs), which is used to store and validate SIWE messages mapped to their nonces as unique identifier. This can be replaced with your custom repository that implements ISessionStorage.
The Nonce is randomly generated by Nethereum using the SiweMessageService.

```csharp
 [AllowAnonymous]
[HttpPost("newsiwemessage")]
public IActionResult GenerateNewSiweMessage([FromBody] string address)
{
    var message = new DefaultSiweMessage();
    message.SetExpirationTime(DateTime.Now.AddMinutes(10));
    message.SetNotBefore(DateTime.Now);
    message.Address = address.ConvertToEthereumChecksumAddress();
    return Ok(_siweMessageService.BuildMessageToSign(message));
}
````

## Authenticating a User
To authentication a user, the signed message will be sent to the Rest API. 
In this example the whole message is validated as follows:

```csharp
[AllowAnonymous]
[HttpPost("authenticate")]
public async Task<IActionResult> Authenticate(AuthenticateRequest authenticateRequest)
{
    var siweMessage = SiweMessageParser.Parse(authenticateRequest.SiweEncodedMessage);
    var signature = authenticateRequest.Signature;
    var validUser = await _siweMessageService.IsUserAddressRegistered(siweMessage);
    if (validUser)
    {
        if (await _siweMessageService.IsMessageSignatureValid(siweMessage, signature))
        {
            if (_siweMessageService.IsMessageTheSameAsSessionStored(siweMessage))
            {
                if (_siweMessageService.HasMessageDateStartedAndNotExpired(siweMessage))
                {
                    var token = _siweJwtAuthorisationService.GenerateToken(siweMessage, signature);
                    return Ok(new AuthenticateResponse
                    {
                        Address = siweMessage.Address,
                        Jwt = token
                    });
                }
                ModelState.AddModelError("Unauthorized", "Expired token");
                return Unauthorized(ModelState);
            }
            ModelState.AddModelError("Unauthorized", "Matching Siwe message with nonce not found");
            return Unauthorized(ModelState);
        }
        ModelState.AddModelError("Unauthorized", "Invalid Signature");
        return Unauthorized(ModelState);
    }

    ModelState.AddModelError("Unauthorized", "Invalid User");
    return Unauthorized(ModelState);
}

```

### IUserService
The first check validates the user is registered (or valid) using Nethereum IUserService ``` var validUser = await _siweMessageService.IsUserAddressRegistered(siweMessage);```.
Your user service can validate the user is a registered user in a smart contract or internal database.
Nethereum provides a preset ERC721BalanceEthereumUserService, that validates that the user has an ERC721 token (NFT balance) https://github.com/Nethereum/Nethereum/blob/master/src/Nethereum.Siwe/UserServices/ERC721BalanceEthereumUserService.cs

## Creation of a JWT Token







