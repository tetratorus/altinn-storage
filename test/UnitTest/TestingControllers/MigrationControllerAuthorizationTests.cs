#nullable disable

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Altinn.Common.AccessToken.Constants;
using Altinn.Common.AccessToken.Services;
using Altinn.Common.PEP.Interfaces;
using Altinn.Platform.Storage.Clients;
using Altinn.Platform.Storage.Controllers;
using Altinn.Platform.Storage.Filters;
using Altinn.Platform.Storage.Models;
using Altinn.Platform.Storage.Repository;
using Altinn.Platform.Storage.UnitTest.Fixture;
using Altinn.Platform.Storage.UnitTest.Mocks;
using Altinn.Platform.Storage.UnitTest.Mocks.Authentication;
using Altinn.Platform.Storage.UnitTest.Mocks.Clients;
using Altinn.Platform.Storage.UnitTest.Mocks.Repository;
using Altinn.Platform.Storage.UnitTest.Utils;
using Altinn.Platform.Storage.Wrappers;
using AltinnCore.Authentication.JwtCookie;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Wolverine;
using Xunit;

namespace Altinn.Platform.Storage.UnitTest.TestingControllers;

public class MigrationControllerAuthorizationTests(
    TestApplicationFactory<MigrationController> factory
) : IClassFixture<TestApplicationFactory<MigrationController>>
{
    private const string _allowedIp = "10.0.0.1";
    private const string _deletePath = "storage/api/v1/migration/delete/";

    private readonly TestApplicationFactory<MigrationController> _factory = factory;

    [Fact]
    public async Task Delete_NoAccessTokenAndNoForwardedHeader_Rejected()
    {
        HttpClient client = GetTestClient(_allowedIp);

        HttpResponseMessage response = await client.PostAsync(_deletePath + Guid.NewGuid(), null);

        AssertRejected(response);
    }

    [Fact]
    public async Task Delete_NoAccessTokenWithSpoofedForwardedHeader_Rejected()
    {
        HttpClient client = GetTestClient("203.0.113.7");
        using HttpRequestMessage request = new(HttpMethod.Post, _deletePath + Guid.NewGuid());
        request.Headers.Add("X-Forwarded-For", $"{_allowedIp}, 203.0.113.7");

        HttpResponseMessage response = await client.SendAsync(request);

        AssertRejected(response);
    }

    [Fact]
    public async Task Delete_AccessTokenFromNonPlatformIssuer_Rejected()
    {
        HttpClient client = GetTestClient(_allowedIp);
        using HttpRequestMessage request = new(HttpMethod.Post, _deletePath + Guid.NewGuid());
        request.Headers.Add("PlatformAccessToken", CreatePlatformSignedToken("ttd"));

        HttpResponseMessage response = await client.SendAsync(request);

        AssertRejected(response);
    }

    [Theory]
    [InlineData("203.0.113.7", null)]
    [InlineData("203.0.113.7", _allowedIp)]
    [InlineData("110.0.0.12", "110.0.0.12")]
    public async Task Delete_PlatformAccessTokenFromIpNotInSafelist_Forbidden(
        string remoteIp,
        string forwardedFor
    )
    {
        HttpClient client = GetTestClient(remoteIp);
        using HttpRequestMessage request = new(HttpMethod.Post, _deletePath + Guid.NewGuid());
        request.Headers.Add("PlatformAccessToken", PrincipalUtil.GetAccessToken());
        if (forwardedFor is not null)
        {
            request.Headers.Add("X-Forwarded-For", forwardedFor);
        }

        HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Delete_PlatformAccessTokenFromSafelistedIp_ReachesAction()
    {
        HttpClient client = GetTestClient(_allowedIp);
        using HttpRequestMessage request = new(HttpMethod.Post, _deletePath + Guid.NewGuid());
        request.Headers.Add("PlatformAccessToken", PrincipalUtil.GetAccessToken());

        HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static void AssertRejected(HttpResponseMessage response)
    {
        Assert.Contains(
            response.StatusCode,
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden }
        );
    }

    private static string CreatePlatformSignedToken(string issuer)
    {
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(
            "platform-org.pfx",
            string.Empty
        );
        SecurityTokenDescriptor descriptor = new()
        {
            Subject = new ClaimsIdentity([
                new Claim(AccessTokenClaimTypes.App, "some-app", ClaimValueTypes.String, issuer),
            ]),
            Expires = DateTime.UtcNow.AddMinutes(1),
            SigningCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256),
            Audience = "altinn.no",
            Issuer = issuer,
        };
        JwtSecurityTokenHandler handler = new();
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private HttpClient GetTestClient(string remoteIp)
    {
        Mock<IInstanceRepository> instanceRepository = new();
        instanceRepository
            .Setup(r => r.GetOne(It.IsAny<Guid>(), false, It.IsAny<CancellationToken>()))
            .ReturnsAsync((InstanceInternal)null);

        var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureTestServices(services =>
            {
                services.AddMockRepositories();
                services.AddSingleton(instanceRepository.Object);
                services.AddSingleton(new Mock<IA2Repository>().Object);
                services.AddSingleton(new Mock<IKeyVaultClientWrapper>().Object);
                services.AddSingleton(new Mock<IMessageBus>().Object);
                services.AddSingleton<
                    IPartiesWithInstancesClient,
                    PartiesWithInstancesClientMock
                >();
                services.AddSingleton<IPDP, PepWithPDPAuthorizationMockSI>();
                services.AddSingleton<
                    IPostConfigureOptions<JwtCookieOptions>,
                    JwtCookiePostConfigureOptionsStub
                >();
                services.AddSingleton<IPublicSigningKeyProvider, PlatformKeyForAnyIssuer>();
                services.AddSingleton(
                    new ClientIpCheckActionFilterAttribute { Safelist = _allowedIp }
                );
                services.AddSingleton<IStartupFilter>(new RemoteIpStartupFilter(remoteIp));
            });
        });

        return factory.CreateClient();
    }

    private sealed class PlatformKeyForAnyIssuer : IPublicSigningKeyProvider
    {
        private readonly PublicSigningKeyProviderMock _inner = new();

        public Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer) =>
            _inner.GetSigningKeys("platform");
    }

    private sealed class RemoteIpStartupFilter(string remoteIp) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.Use(
                    (context, nextMiddleware) =>
                    {
                        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
                        return nextMiddleware();
                    }
                );
                next(app);
            };
    }
}
