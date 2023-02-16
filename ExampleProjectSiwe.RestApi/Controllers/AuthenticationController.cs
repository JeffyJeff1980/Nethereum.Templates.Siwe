using ExampleProjectSiwe.RestApi.Authorisation;
using ExampleProjectSiwe.RestApi.Models;
using Microsoft.AspNetCore.Mvc;
using Nethereum.Siwe;
using Nethereum.Siwe.Core;
using Nethereum.Util;
using System.Security.Claims;

namespace ExampleProjectSiwe.RestApi.Controllers
{
  [Authorize]
  [ApiController]
  [Route("[controller]")]
  public class AuthenticationController : Controller
  {
    private readonly ISiweJwtAuthorisationService _siweJwtAuthorisationService;
    private readonly SiweMessageService _siweMessageService;

    public AuthenticationController(SiweMessageService siweMessageService, ISiweJwtAuthorisationService siweJwtAuthorisationService)
    {
      _siweMessageService = siweMessageService;
      _siweJwtAuthorisationService = siweJwtAuthorisationService;
    }

    public class AuthenticateRequest
    {
      public string SiweEncodedMessage { get; set; }
      public string Signature { get; set; }
    }

    public class AuthenticateResponse
    {
      public string Address { get; set; }
      public string Jwt { get; set; }
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
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

    [AllowAnonymous]
    [HttpPost("message")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult GenerateNewSiweMessage([FromBody] string address)
    {
      var addressUtil = new AddressUtil();
      var isValid = addressUtil.IsValidEthereumAddressHexFormat(address);

      if (!isValid)
      {
        ModelState.AddModelError("InvalidAddress", "Invalid Address");
        return BadRequest(ModelState);
      }

      var message = new DefaultSiweMessage();
      message.SetExpirationTime(DateTime.Now.AddMinutes(10));
      message.SetNotBefore(DateTime.Now);
      message.Address = address.ConvertToEthereumChecksumAddress();
      return Ok(_siweMessageService.BuildMessageToSign(message));
    }

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult LogOut()
    {
      var siweMessage = SiweJwtMiddleware.GetSiweMessageFromContext(HttpContext);
      _siweMessageService.InvalidateSession(siweMessage);
      return Ok();
    }

    [HttpGet("user")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult GetAuthenticatedUser()
    {
      //ethereum wallet address
      var address = SiweJwtMiddleware.GetEthereumAddressFromContext(HttpContext);

      if (address != null)
      {
        //First get user claims
        var claims = ClaimsPrincipal.Current?.Identities.First().Claims.ToList();

        //Filter specific claims
        var username = claims?.FirstOrDefault(x => x.Type.Equals("UserName", StringComparison.OrdinalIgnoreCase))?.Value;
        var email = claims?.FirstOrDefault(x => x.Type.Equals("Email", StringComparison.OrdinalIgnoreCase))?.Value;

        return Ok(new User { Username = username, Email = email, WalletAddress = address });
      }

      //this should not happen
      return Forbid();
    }
  }
}