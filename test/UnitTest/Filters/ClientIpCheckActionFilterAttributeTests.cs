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

namespace Altinn.Platform.Storage.UnitTest.Filters;

public class ClientIpCheckActionFilterAttributeTests
{
    [Theory]
    [InlineData("", null, "10.0.0.1")]
    [InlineData("", "10.0.0.1", "192.168.0.5")]
    [InlineData("not-an-ip", "10.0.0.1", "192.168.0.5")]
    [InlineData("10.0.0.1", null, null)]
    [InlineData("10.0.0.1", null, "10.0.0.2")]
    [InlineData("10.0.0.1", "10.0.0.2", "10.0.0.1")]
    [InlineData("10.0.0.1", "10.0.0.1, 10.0.0.2", "10.0.0.1")]
    [InlineData("10.0.0.1", "10.0.0.11", "10.0.0.1")]
    [InlineData("10.0.0.1", "110.0.0.1", "10.0.0.1")]
    [InlineData("10.0.0.1", "garbage", "10.0.0.1")]
    public void OnActionExecuting_Rejected_Forbid(
        string safelist,
        string forwardedFor,
        string remoteIp
    )
    {
        ActionExecutingContext context = CreateContext(forwardedFor, remoteIp);
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = safelist };

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    [Theory]
    [InlineData("10.0.0.1", null, "10.0.0.1")]
    [InlineData("10.0.0.1", null, "::ffff:10.0.0.1")]
    [InlineData("10.0.0.1;10.0.0.2", "10.0.0.2", "192.168.0.5")]
    [InlineData(" 10.0.0.1 ; 10.0.0.2 ", "10.0.0.1", "192.168.0.5")]
    [InlineData("10.0.0.1", "203.0.113.9, 10.0.0.1", "192.168.0.5")]
    [InlineData("10.0.0.1", "10.0.0.1:51234", "192.168.0.5")]
    [InlineData("2001:db8::1", "2001:db8::1", "192.168.0.5")]
    public void OnActionExecuting_Allowed_Continues(
        string safelist,
        string forwardedFor,
        string remoteIp
    )
    {
        ActionExecutingContext context = CreateContext(forwardedFor, remoteIp);
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = safelist };

        filter.OnActionExecuting(context);

        Assert.Null(context.Result);
    }

    private static ActionExecutingContext CreateContext(string forwardedFor, string remoteIp)
    {
        DefaultHttpContext httpContext = new();
        if (forwardedFor != null)
        {
            httpContext.Request.Headers["X-Forwarded-For"] = forwardedFor;
        }

        if (remoteIp != null)
        {
            httpContext.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
        }

        ActionContext actionContext = new(httpContext, new RouteData(), new ActionDescriptor());
        return new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            new Dictionary<string, object>(),
            new object()
        );
    }
}
