#nullable disable

using System.Collections.Generic;
using System.Net;
using Altinn.Platform.Storage.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace Altinn.Platform.Storage.UnitTest.HelperTests;

public class ClientIpCheckActionFilterAttributeTests
{
    [Theory]
    [InlineData("10.0.0.1;10.0.0.2", "10.0.0.2", true)]
    [InlineData("10.0.0.1;10.0.0.2", "10.0.0.3", false)]
    [InlineData("10.0.0.0/24", "10.0.0.200", true)]
    [InlineData("10.0.0.0/24", "10.0.1.1", false)]
    [InlineData("10.0.0.1", "::ffff:10.0.0.1", true)]
    [InlineData("10.0.0.1", "10.0.0.10", false)]
    [InlineData("10.0.0.1", "110.0.0.1", false)]
    [InlineData("", "10.0.0.1", false)]
    [InlineData(null, "10.0.0.1", false)]
    public void OnActionExecuting_ChecksRemoteIpAgainstSafelist(
        string safelist,
        string remoteIp,
        bool expectedAllowed
    )
    {
        ActionExecutingContext context = CreateContext(IPAddress.Parse(remoteIp));
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = safelist };

        filter.OnActionExecuting(context);

        Assert.Equal(expectedAllowed, context.Result is null);
        if (!expectedAllowed)
        {
            Assert.IsType<ForbidResult>(context.Result);
        }
    }

    [Fact]
    public void OnActionExecuting_IgnoresXForwardedForHeader()
    {
        ActionExecutingContext context = CreateContext(IPAddress.Parse("192.168.1.50"));
        context.HttpContext.Request.Headers["X-Forwarded-For"] = "10.0.0.1";
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    [Fact]
    public void OnActionExecuting_ForbidsWhenRemoteIpIsUnknown()
    {
        ActionExecutingContext context = CreateContext(null);
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    private static ActionExecutingContext CreateContext(IPAddress remoteIp)
    {
        DefaultHttpContext httpContext = new();
        httpContext.Connection.RemoteIpAddress = remoteIp;
        ActionContext actionContext = new(httpContext, new RouteData(), new ActionDescriptor());
        return new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            new Dictionary<string, object>(),
            new object()
        );
    }
}
