#nullable disable

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Altinn.Common.AccessToken.Services;
using Altinn.Common.PEP.Interfaces;
using Altinn.Platform.Storage.Clients;
using Altinn.Platform.Storage.Configuration;
using Altinn.Platform.Storage.Controllers;
using Altinn.Platform.Storage.Interface.Models;
using Altinn.Platform.Storage.Messages;
using Altinn.Platform.Storage.Repository;
using Altinn.Platform.Storage.UnitTest.Fixture;
using Altinn.Platform.Storage.UnitTest.Mocks;
using Altinn.Platform.Storage.UnitTest.Mocks.Authentication;
using Altinn.Platform.Storage.UnitTest.Mocks.Repository;
using Altinn.Platform.Storage.UnitTest.Utils;
using Altinn.Platform.Storage.Wrappers;
using AltinnCore.Authentication.JwtCookie;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Wolverine;
using Xunit;

namespace Altinn.Platform.Storage.UnitTest.TestingControllers;

public class InstanceEventsControllerTests
    : IClassFixture<TestApplicationFactory<InstanceEventsController>>
{
    private readonly TestApplicationFactory<InstanceEventsController> _factory;

    public InstanceEventsControllerTests(TestApplicationFactory<InstanceEventsController> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Post_WhenInstanceEventInstanceIdNotSet_Returns400BadRequest()
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(3, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        InstanceEvent instance = new InstanceEvent { InstanceId = null };

        // Act
        JsonContent content = JsonContent.Create(
            instance,
            new MediaTypeHeaderValue("application/json")
        );
        HttpResponseMessage response = await client.PostAsync(requestUri, content);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Add a new event to an instance.
    /// </summary>
    [Fact]
    public async Task Post_CreateNewEvent_ReturnsCreated()
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(3, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        InstanceEvent instance = new InstanceEvent
        {
            InstanceId = "3c42ee2a-9464-42a8-a976-16eb926bd20a",
        };

        // Act
        JsonContent content = JsonContent.Create(
            instance,
            new MediaTypeHeaderValue("application/json")
        );
        HttpResponseMessage response = await client.PostAsync(requestUri, content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Post_CreateNewEventWithWolverineEnabledAndWolverineThrows_ReturnsCreated()
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        Mock<IMessageBus> messageBusMock = new Mock<IMessageBus>();
        messageBusMock
            .Setup(s => s.PublishAsync(It.IsAny<SyncInstanceToDialogportenCommand>(), null))
            .ThrowsAsync(new Exception());

        HttpClient client = GetTestClient(enableWolverine: true);
        string token = PrincipalUtil.GetToken(3, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        InstanceEvent instance = new InstanceEvent
        {
            InstanceId = "3c42ee2a-9464-42a8-a976-16eb926bd20a",
        };

        // Act
        JsonContent content = JsonContent.Create(
            instance,
            new MediaTypeHeaderValue("application/json")
        );
        HttpResponseMessage response = await client.PostAsync(requestUri, content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>
    /// Test case: User has to low authentication level.
    /// Expected: Returns status forbidden.
    /// </summary>
    [Fact]
    public async Task Post_UserHasTooLowAuthLv_ReturnStatusForbidden()
    {
        // Arrange
        string requestUri =
            $"storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(3, 1337, 0);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        InstanceEvent instance = new InstanceEvent();

        // Act
        HttpResponseMessage response = await client.PostAsync(
            requestUri,
            JsonContent.Create(instance, new MediaTypeHeaderValue("application/json"))
        );

        if (response.StatusCode.Equals(HttpStatusCode.InternalServerError))
        {
            string serverContent = await response.Content.ReadFromJsonAsync<string>();
            Assert.Equal("Hei", serverContent);
        }

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Test case: Response is deny.
    /// Expected: Returns status forbidden.
    /// </summary>
    [Fact]
    public async Task Post_ResponseIsDeny_ReturnStatusForbidden()
    {
        // Arrange
        string requestUri =
            $"storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(-1, 1);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        InstanceEvent instance = new InstanceEvent();

        // Act
        HttpResponseMessage response = await client.PostAsync(
            requestUri,
            JsonContent.Create(instance, new MediaTypeHeaderValue("application/json"))
        );

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Test case: User has to low authentication level.
    /// Expected: Returns status forbidden.
    /// </summary>
    [Fact]
    public async Task GetOne_UserHasToLowAuthLv_ReturnStatusForbidden()
    {
        // Arrange
        string eventGuid = "c8a44353-114a-48fc-af8f-b85392793cb2";
        string requestUri =
            $"storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/{eventGuid}";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(3, 1337, 0);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Test case: Response is deny.
    /// Expected: Returns status forbidden.
    /// </summary>
    [Fact]
    public async Task GetOne_ResponseIsDeny_ReturnStatusForbidden()
    {
        string eventGuid = "9f07c256-a344-490b-b42b-1c855a83f6fc";
        string requestUri =
            $"storage/api/v1/instances/1337/a6020470-2200-4448-bed9-ef46b679bdb8/events/{eventGuid}";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(-1, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Test case: User has to low authentication level.
    /// Expected: Returns status forbidden.
    /// </summary>
    [Fact]
    public async Task Get_UserHasToLowAuthLv_ReturnStatusForbidden()
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(3, 1337, 0);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Test case: Response is deny.
    /// Expected: Returns status forbidden.
    /// </summary>
    [Fact]
    public async Task Get_ResponseIsDeny_ReturnStatusForbidden()
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events/";

        HttpClient client = GetTestClient();
        string token = PrincipalUtil.GetToken(-1, 1);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Test case: Get events with every combination of present and absent from/to bounds.
    /// Expected: Each supplied bound is passed on to the repository and each missing bound is left open.
    /// </summary>
    [Theory]
    [InlineData(null, null)]
    [InlineData("2019-05-03T11:55:23", null)]
    [InlineData(null, "2019-05-03T12:55:23")]
    [InlineData("2019-05-03T11:55:23", "2019-05-03T12:55:23")]
    [InlineData("2019-05-03T11:55:23", "2019-05-03T11:55:23")]
    public async Task Get_WithOptionalTimeBounds_PassesEachSuppliedBoundToRepository(
        string from,
        string to
    )
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events"
            + BuildTimeBoundQuery(from, to);

        DateTime? expectedFrom = from == null ? null : ToUtc(from);
        DateTime? expectedTo = to == null ? null : ToUtc(to);

        Mock<IInstanceEventRepository> repositoryMock = new Mock<IInstanceEventRepository>();
        repositoryMock
            .Setup(r =>
                r.ListInstanceEvents(
                    It.IsAny<Guid>(),
                    It.IsAny<string[]>(),
                    It.IsAny<DateTime?>(),
                    It.IsAny<DateTime?>()
                )
            )
            .ReturnsAsync([]);

        HttpClient client = GetTestClient(instanceEventRepositoryMock: repositoryMock);
        string token = PrincipalUtil.GetToken(3, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        repositoryMock.Verify(
            r =>
                r.ListInstanceEvents(
                    Guid.Parse("3c42ee2a-9464-42a8-a976-16eb926bd20a"),
                    It.IsAny<string[]>(),
                    expectedFrom,
                    expectedTo
                ),
            Times.Once
        );
    }

    /// <summary>
    /// Test case: Get events with a from/to bound that is not a valid timestamp, alone or together with a valid one.
    /// Expected: Returns bad request without querying the repository.
    /// </summary>
    [Theory]
    [InlineData("not-a-date", null)]
    [InlineData(null, "not-a-date")]
    [InlineData("not-a-date", "2019-05-03T12:55:23")]
    [InlineData("2019-05-03T11:55:23", "not-a-date")]
    public async Task Get_WithInvalidTimeBound_ReturnsBadRequest(string from, string to)
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events"
            + BuildTimeBoundQuery(from, to);

        Mock<IInstanceEventRepository> repositoryMock = new Mock<IInstanceEventRepository>();
        HttpClient client = GetTestClient(instanceEventRepositoryMock: repositoryMock);
        string token = PrincipalUtil.GetToken(3, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            "Unable to perform query. Invalid format for time span. Use string format of UTC.",
            await response.Content.ReadFromJsonAsync<string>()
        );
        repositoryMock.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Test case: Get events with a from bound that is later than the to bound.
    /// Expected: Returns bad request without querying the repository.
    /// </summary>
    [Fact]
    public async Task Get_WithFromLaterThanTo_ReturnsBadRequest()
    {
        // Arrange
        string requestUri =
            "storage/api/v1/instances/1337/3c42ee2a-9464-42a8-a976-16eb926bd20a/events"
            + BuildTimeBoundQuery("2019-05-03T12:55:23", "2019-05-03T11:55:23");

        Mock<IInstanceEventRepository> repositoryMock = new Mock<IInstanceEventRepository>();
        HttpClient client = GetTestClient(instanceEventRepositoryMock: repositoryMock);
        string token = PrincipalUtil.GetToken(3, 1337);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Act
        HttpResponseMessage response = await client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            "Unable to perform query. The 'from' timestamp must not be later than the 'to' timestamp.",
            await response.Content.ReadFromJsonAsync<string>()
        );
        repositoryMock.VerifyNoOtherCalls();
    }

    private static string BuildTimeBoundQuery(string from, string to)
    {
        List<string> parameters = [];
        if (from != null)
        {
            parameters.Add($"from={Uri.EscapeDataString(from)}");
        }

        if (to != null)
        {
            parameters.Add($"to={Uri.EscapeDataString(to)}");
        }

        return parameters.Count == 0 ? string.Empty : "?" + string.Join("&", parameters);
    }

    private static DateTime ToUtc(string timestamp) =>
        DateTime.SpecifyKind(
            DateTime.Parse(timestamp, CultureInfo.InvariantCulture),
            DateTimeKind.Utc
        );

    private HttpClient GetTestClient(
        Mock<IMessageBus> messageBusMock = null,
        bool enableWolverine = false,
        Mock<IInstanceEventRepository> instanceEventRepositoryMock = null
    )
    {
        // No setup required for these services. They are not in use by the InstanceEventController
        Mock<IKeyVaultClientWrapper> keyVaultWrapper = new Mock<IKeyVaultClientWrapper>();
        Mock<IPartiesWithInstancesClient> partiesWrapper = new Mock<IPartiesWithInstancesClient>();
        Mock<IMessageBus> busMock = messageBusMock ?? new Mock<IMessageBus>();

        HttpClient client = _factory
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    services.AddMockRepositories();
                    if (instanceEventRepositoryMock != null)
                    {
                        services.AddSingleton(instanceEventRepositoryMock.Object);
                    }

                    services.AddSingleton(keyVaultWrapper.Object);
                    services.AddSingleton(partiesWrapper.Object);
                    services.AddSingleton<IPDP, PepWithPDPAuthorizationMockSI>();
                    services.AddSingleton<
                        IPublicSigningKeyProvider,
                        PublicSigningKeyProviderMock
                    >();
                    services.AddSingleton<
                        IPostConfigureOptions<JwtCookieOptions>,
                        JwtCookiePostConfigureOptionsStub
                    >();
                    services.AddSingleton(busMock.Object);
                    services.Configure<WolverineSettings>(opts =>
                    {
                        opts.EnableSending = enableWolverine;
                    });
                });
            })
            .CreateClient();

        return client;
    }
}
