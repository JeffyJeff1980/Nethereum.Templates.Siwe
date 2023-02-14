using ExampleProjectSiwe.RestApi.Authorisation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using Nethereum.Siwe;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var services = builder.Services;

#region Authentication

builder.Services.AddAuthentication(options =>
{
  options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
  o.TokenValidationParameters = new TokenValidationParameters
  {
    ValidIssuer = builder.Configuration["Jwt:Issuer"],
    ValidAudience = builder.Configuration["Jwt:Audience"],
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = false,
    ValidateIssuerSigningKey = true
  };
});

#endregion Authentication

#region Add Swagger
builder.Services.AddSwaggerGen(c =>
{
  c.SwaggerDoc("v1", new OpenApiInfo { Title = "MyWebsite Api", Version = "v1" });
  c.AddSecurityDefinition("token", new OpenApiSecurityScheme
  {
    Type = SecuritySchemeType.ApiKey,
    In = ParameterLocation.Header,
    Name = HeaderNames.Authorization,
    Scheme = "Bearer"
  });
});
#endregion Add Swagger

# region Controllers, OData & Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddHttpContextAccessor();
#endregion

#region CORS
builder.Services.AddCors(options =>
{
  options.AddPolicy("AllowOrigin", c =>
      c.AllowAnyOrigin()
      .AllowAnyMethod()
      .AllowAnyHeader()
    );
});
#endregion

services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

var inMemorySessionNonceStorage = new InMemorySessionNonceStorage();
services.AddScoped<ISessionStorage>(x => inMemorySessionNonceStorage);

//we don't need a ethereumUserService (db or contract), ignore address 1271 validation web3
services.AddScoped(x => new SiweMessageService(inMemorySessionNonceStorage, null, null));
services.AddScoped<ISiweJwtAuthorisationService, SiweJwtAuthorisationService>();

#region Build App
var app = builder.Build();
#endregion

#region Use Swagger
// Configure the HTTP request pipeline.
app.UseSwagger();
if (app.Environment.IsDevelopment())
{
  app.UseSwaggerUI();
}
else if (app.Environment.IsProduction())
{
  app.UseSwaggerUI(c =>
  {
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "SwapLand.Api v1");
    c.RoutePrefix = "swagger";
  });
}

#endregion

#region Use CORS
app.UseCors("AllowOrigin");
#endregion
// Configure the HTTP request pipeline.

//app.UseAuthorization();
app.UseCors(configure =>
{
  configure
      .AllowAnyOrigin()
      .AllowAnyMethod()
      .AllowAnyHeader();
});

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.UseMiddleware<SiweJwtMiddleware>();
app.Run();